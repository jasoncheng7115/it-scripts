from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.hooks.base import BaseHook
from airflow.models import Variable
import proxmoxer
import json
import time
import random
from typing import Dict, List, Tuple
import logging
from croniter import croniter
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

def parse_schedule(schedule_str: str) -> List[Tuple[str, str, int]]:
    schedules = []
    for item in schedule_str.split(','):
        if not item.strip():
            continue
        vmid, interval, retention = item.strip().split(':')
        
        unit = interval[-1]
        value = int(interval[:-1])
        if unit == 'h':
            cron = f"0 */{value} * * *"  # 小時
        elif unit == 'm':
            cron = f"*/{value} * * * *"  # 分鐘
        elif unit == 'd':
            cron = f"0 0 */{value} * *"  # 天
        else:
            raise ValueError(f"Invalid time unit: {unit}")
            
        schedules.append((vmid, cron, int(retention)))
    return schedules

def get_node_timezone(proxmox, node: str) -> str:
   """從 PVE 節點取得時區設定"""
   try:
       node_time = proxmox.nodes(node).time.get()
       return node_time.get('timezone', 'UTC')
   except Exception as e:
       logger.warning(f"無法取得節點 {node} 時區: {e}")
       return 'UTC'


def parse_timezone_offset(tz_str: str) -> int:
    """解析時區字串並傳回小時偏移量"""
    try:
        if tz_str == 'UTC' or not tz_str:
            return 0
            
        # 處理標準格式如 Asia/Taipei
        std_zones = {
            'Asia/Taipei': 8,
            'Asia/Shanghai': 8, 
            'Asia/Singapore': 8,
            'Asia/Tokyo': 9,
            'America/New_York': -5,
            'Europe/London': 0,
            'Europe/Paris': 1
        }
        if tz_str in std_zones:
            return std_zones[tz_str]
            
        # 處理 UTC±XX 格式
        if tz_str.startswith(('UTC+', 'UTC-')):
            return int(tz_str[3:])
            
        logger.warning(f"無法解析時區: {tz_str}, 使用 UTC")
        return 0
            
    except Exception as e:
        logger.error(f"解析時區錯誤: {e}")
        return 0

def get_system_configs() -> Dict:
    storage_threshold = int(Variable.get("pve_snapshot_storage_threshold", default_var=10))
    io_wait_threshold = int(Variable.get("pve_snapshot_io_wait_threshold", default_var=15))
    schedule_margin = int(Variable.get("pve_snapshot_schedule_margin", default_var=1))
    
    return {
        "storage_threshold": storage_threshold,
        "io_wait_threshold": io_wait_threshold,
        "schedule_check_margin": schedule_margin
    }

def get_snapshot_schedules() -> List[Tuple[str, str, int]]:
    try:
        schedule_str = Variable.get("pve_snapshot_schedule")
        logger.info(f"Read schedule string: {schedule_str}")
        schedules = parse_schedule(schedule_str)
        logger.info(f"Parsed schedules: {schedules}")
        return schedules
    except Exception as e:
        logger.error(f"Error reading snapshot schedules: {e}")
        return []

def get_retry_configs() -> Dict:
    retry_interval = int(Variable.get("pve_snapshot_retry_interval", default_var=2))
    max_retries = int(Variable.get("pve_snapshot_retry_max", default_var=2))
    
    return {
        "retry_interval": retry_interval,
        "max_retries": max_retries
    }

def get_snapshot_name_format() -> str:
    try:
        return Variable.get("pve_snapshot_name_format")
    except:
        return "auto_snap_{vmid}_%Y%m%d_%H%M%S"

def get_failed_snapshots() -> Dict:
    try:
        return Variable.get("pve_snapshot_failed", deserialize_json=True)
    except:
        return {}

def update_failed_snapshots(failed_dict: Dict):
    Variable.set("pve_snapshot_failed", json.dumps(failed_dict))

def check_vm_status(proxmox, node: str, vmid: int, resource_type: str) -> bool:
    """
    回傳 True 代表可進行 snapshot（狀態為 running、且無 lock）；
    回傳 False 則代表要跳過該 VM/CT。
    """
    try:
        # 依照不同 resource_type 呼叫不同 API
        if resource_type == 'CT':
            raw_status = proxmox.nodes(node).lxc(vmid).status.current.get()
        else:
            raw_status = proxmox.nodes(node).qemu(vmid).status.current.get()
        
        # 部分版本可能回傳 list；若是 list，嘗試取得第一個元素當做狀態
        if isinstance(raw_status, list):
            if len(raw_status) > 0 and isinstance(raw_status[0], dict):
                status_dict = raw_status[0]
            else:
                logger.warning(f"{resource_type} {vmid}: unexpected list response, skip.")
                return False
        elif isinstance(raw_status, dict):
            status_dict = raw_status
        else:
            logger.warning(f"{resource_type} {vmid}: unknown status format, skip.")
            return False
        
        vm_status = status_dict.get('status', None)
        lock_state = status_dict.get('lock', None)

        # 檢查是否 running
        if vm_status != 'running':
            logger.warning(f"{resource_type} {vmid} is not running, current status: {vm_status}")
            # 如果你允許 snapshot 在關機狀態也可以做，這裡可改成：return True
            return False
        
        # 檢查是否 locked
        if lock_state is not None:
            logger.warning(f"{resource_type} {vmid} is locked: {lock_state}")
            return False

        # 若都沒問題
        return True

    except Exception as e:
        logger.error(f"Status check error for {resource_type} {vmid}: {str(e)}")
        return False


def get_vm_storages(proxmox, node: str, vmid: int) -> List[str]:
    try:
        vm_config = proxmox.nodes(node).qemu(vmid).config.get()
        storages = []
        
        for key, value in vm_config.items():
            time.sleep(0.005)
            if key.startswith(('virtio', 'sata', 'scsi', 'ide')) and isinstance(value, str):
                if ':' in value:
                    storage = value.split(',')[0].split(':')[0]
                    if storage:
                        storages.append(storage)
        
        if not storages:
            logger.warning(f"No storage devices found for VM {vmid}")
            
        return storages
    except Exception as e:
        logger.error(f"Error getting storages for VM {vmid}: {str(e)}")
        raise

def check_storage_space(proxmox, node: str, vmid: int, storages: List[str]) -> bool:
    try:
        sys_configs = get_system_configs()
        
        for storage in storages:
            time.sleep(0.005)
            storage_status = proxmox.nodes(node).storage(storage).status.get()
            available_percent = (storage_status['avail'] / storage_status['total']) * 100
            logger.info(f"Storage {storage} available space: {available_percent:.2f}%")
            
            if available_percent < sys_configs['storage_threshold']:
                logger.warning(f"VM {vmid} on node {node}, storage {storage} available space too low: {available_percent:.2f}%")
                return False
                
        return True
    except Exception as e:
        logger.error(f"Storage space check error for VM {vmid}: {str(e)}")
        return False

def check_io_wait(proxmox, node: str) -> bool:
    try:
        sys_configs = get_system_configs()
        node_status = proxmox.nodes(node).status.get()
        io_wait = float(node_status.get('wait', 0))
        
        logger.info(f"Node {node} IO wait: {io_wait}%")
        if io_wait >= sys_configs['io_wait_threshold']:
            logger.warning(f"Node {node} IO wait too high: {io_wait}%")
            return False
            
        return True
    except Exception as e:
        logger.error(f"IO wait check error for node {node}: {str(e)}")
        return False

def create_snapshot(proxmox, node: str, vmid: int, name: str, include_memory: bool, resource_type: str) -> bool:
   """建立 VM/CT 快照
   
   Args:
       proxmox: Proxmox API 連線物件
       node: PVE 節點名稱
       vmid: VM/CT ID
       name: 快照名稱
       include_memory: 是否包含記憶體狀態 (僅 VM 有效)
       resource_type: 資源類型 ('VM' 或 'CT')
   
   Returns:
       bool: 是否成功建立快照
   """
   try:
       # 取得節點時區
       node_tz = get_node_timezone(proxmox, node)
       current_time = datetime.now().astimezone(timezone(timedelta(hours=parse_timezone_offset(node_tz))))
       
       if resource_type == 'CT':
           snapapi = proxmox.nodes(node).lxc(vmid).snapshot
           status = proxmox.nodes(node).lxc(vmid).status.current.get()
           if status.get('lock'):
               logger.error(f"CT {vmid} is locked, cannot create snapshot")
               return False
           snapapi.create(
               snapname=name,
               description=f"Auto snapshot created by Airflow at {current_time.isoformat()}"
           )
       else:
           snapapi = proxmox.nodes(node).qemu(vmid).snapshot
           status = proxmox.nodes(node).qemu(vmid).status.current.get()
           if status.get('lock'):
               logger.error(f"VM {vmid} is locked, cannot create snapshot")
               return False
           snapapi.create(
               snapname=name,
               vmstate=1 if include_memory else 0,
               description=f"Auto snapshot created by Airflow at {current_time.isoformat()}"
           )
           
       logger.info(f"Successfully created snapshot {name} for {resource_type} {vmid}")
       return True
       
   except Exception as e:
       logger.error(f"Snapshot creation error for {resource_type} {vmid}: {str(e)}")
       return False

def clean_old_snapshots(proxmox, node: str, vmid: int, retention: int, resource_type: str) -> None:
    try:
        if resource_type == 'CT':
            snapapi = proxmox.nodes(node).lxc(vmid).snapshot
            status = proxmox.nodes(node).lxc(vmid).status.current.get()
        else:
            snapapi = proxmox.nodes(node).qemu(vmid).snapshot
            status = proxmox.nodes(node).qemu(vmid).status.current.get()
             
        if status.get('lock'):
            logger.error(f"{resource_type} {vmid} is locked, cannot delete snapshots")
            return
            
        snapshots = snapapi.get()
        auto_snaps = [s for s in snapshots if s['name'].startswith('auto_snap_')]
        auto_snaps.sort(key=lambda x: x['name'])
        
        logger.info(f"Found {len(auto_snaps)} auto snapshots for {resource_type} {vmid}")
        delete_count = max(0, len(auto_snaps) - retention)
        if delete_count > 0:
            logger.info(f"Will delete {delete_count} old snapshots for {resource_type} {vmid}")
            
        while len(auto_snaps) > retention:
            time.sleep(0.005)
            oldest = auto_snaps.pop(0)
            try:
                # 不再檢查 snapshot config，直接執行刪除
                snapapi(oldest['name']).delete()
                logger.info(f"Successfully deleted snapshot {oldest['name']} for {resource_type} {vmid}")
            except Exception as e:
                logger.error(f"Failed to delete snapshot {oldest['name']} for {resource_type} {vmid}: {str(e)}")
    except Exception as e:
        logger.error(f"Error cleaning old snapshots for {resource_type} {vmid}: {str(e)}")


def should_snapshot_now(schedule: str, current_time: datetime, vmid: str) -> bool:
    current_time = current_time.astimezone(timezone(timedelta(hours=8)))
    cron = croniter(schedule, current_time)
    prev_time = cron.get_prev(datetime)
    next_time = cron.get_next(datetime)
    
    time_diff = (current_time - prev_time.replace(tzinfo=timezone(timedelta(hours=8)))).total_seconds() / 60
    sys_configs = get_system_configs()
    margin = sys_configs['schedule_check_margin']
    
    logger.info(f"{vmid}: Schedule check - prev: {prev_time}, next: {next_time}, diff: {time_diff:.2f}m")
    
    # 檢查是否在允許範圍內（接近0分鐘或接近排程間隔）
    should_run = time_diff < margin or abs(time_diff - (next_time - prev_time).total_seconds() / 60) < margin
    
    if should_run:
        logger.info(f"{vmid}: Should run snapshot now")
    else:
        logger.info(f"{vmid}: Not scheduled for snapshot now")
    return should_run


def execute_snapshot(**context):
    current_time = context['execution_date'].astimezone(timezone(timedelta(hours=8)))  # 轉換到 UTC+8
    logger.info(f"Starting snapshot execution at {current_time}")
    
    def check_resource(vmid: str, resource_type: str):
        logger.info(f"Checking {resource_type} {vmid} against schedule")
        schedule_info = next((s for s in snapshot_schedules if s[0] == vmid), None)
        if schedule_info:
            logger.info(f"Found schedule for {resource_type} {vmid}: {schedule_info}")
            if should_snapshot_now(schedule_info[1], current_time, vmid):
                vms_to_snapshot.append({
                    'node': node['node'],
                    'vmid': int(vmid),
                    'retention': schedule_info[2],
                    'type': resource_type
                })
        else:
            logger.info(f"No schedule found for {resource_type} {vmid}")
    
    try:

        conn = BaseHook.get_connection('proxmox_default')
        extra = conn.extra or "{}"
        extra_dict = json.loads(extra)
        token_name = extra_dict.get('token_name', '')

        proxmox = proxmoxer.ProxmoxAPI(
            conn.host,
            user=conn.login,  # 'airflow@pve'
            token_name=token_name,
            token_value=conn.password,
            verify_ssl=False
        )

        nodes = proxmox.nodes.get()
        logger.info(f"Successfully connected to PVE API. Found {len(nodes)} nodes")
    except Exception as e:
        logger.error(f"Failed to connect to PVE API: {str(e)}")
        return
    
    try:
        snapshot_schedules = get_snapshot_schedules()
        logger.info(f"Loaded snapshot schedules: {snapshot_schedules}")
    except Exception as e:
        logger.error(f"Failed to load snapshot schedules: {str(e)}")
        return
    
    name_format = get_snapshot_name_format()
    vms_to_snapshot = []
    
    for node in proxmox.nodes.get():
        time.sleep(0.005)
        logger.info(f"Checking node: {node['node']}")
        
        # 檢查 VMs
        try:
            vms = proxmox.nodes(node['node']).qemu.get()
            logger.info(f"Found {len(vms)} VMs on node {node['node']}")
            for vm in vms:
                time.sleep(0.005)
                vmid = str(vm['vmid'])
                check_resource(vmid, 'VM')
        except Exception as e:
            logger.error(f"Error checking VMs on node {node['node']}: {str(e)}")
        
        # 檢查 CTs
        try:
            cts = proxmox.nodes(node['node']).lxc.get()
            logger.info(f"Found {len(cts)} CTs on node {node['node']}")
            for ct in cts:
                time.sleep(0.005)
                vmid = str(ct['vmid'])
                check_resource(vmid, 'CT')
        except Exception as e:
            logger.error(f"Error checking CTs on node {node['node']}: {str(e)}")
    
    logger.info(f"Found {len(vms_to_snapshot)} resources to snapshot: {vms_to_snapshot}")
    
    for vm in vms_to_snapshot:
        time.sleep(0.005)
        vmid = vm['vmid']
        node = vm['node']
        str_vmid = str(vmid)
        resource_type = vm['type']
        
        # 檢查狀態
        if not check_vm_status(proxmox, node, vmid, resource_type):
            logger.info(f"Skipping {resource_type} {vmid} as it is not running or is locked")
            continue
            
        try:
            if resource_type == 'CT':
                storages = [proxmox.nodes(node).lxc(vmid).config.get()['rootfs'].split(':')[0]]
            else:
                storages = get_vm_storages(proxmox, node, vmid)
                
            if not storages:
                logger.error(f"No valid storage found for {resource_type} {vmid}, skipping")
                continue
        except Exception as e:
            logger.error(f"Error getting storages for {resource_type} {vmid}: {str(e)}")
            continue
            
        if not check_storage_space(proxmox, node, vmid, storages):
            logger.error(f"Insufficient storage space for {resource_type} {vmid}")
            continue
            
        if not check_io_wait(proxmox, node):
            logger.error(f"IO wait too high for node {node}, skipping {resource_type} {vmid}")
            continue
        
        snapshot_name = current_time.strftime(
            name_format.format(vmid=vmid)
        )
        
        success = create_snapshot(proxmox, node, vmid, snapshot_name, False, resource_type)
        if success:
            logger.info(f"Successfully created snapshot for {resource_type} {vmid}")
            # 等待 2-5 秒
            wait_time = random.randint(1, 2)
            logger.info(f"Waiting {wait_time} seconds before cleaning old snapshots")
            time.sleep(wait_time)
            clean_old_snapshots(proxmox, node, vmid, vm['retention'], resource_type)

        else:
            logger.error(f"Failed to create snapshot for {resource_type} {vmid}")

default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 0,
}

with DAG(
    'pve_auto_snapshot',
    default_args=default_args,
    description='Automated PVE VM/CT snapshot management',
    schedule_interval='* * * * *',
    start_date=datetime(2024, 1, 1),
    catchup=False,
    tags=['pve', 'snapshot']
) as dag:
    
    execute_snapshot_task = PythonOperator(
        task_id='execute_snapshot',
        python_callable=execute_snapshot,
        provide_context=True,
        dag=dag
    )
            

# Jason Tools (www.jason.tools) - Jason Cheng (jason@jason.tools)
from airflow import DAG, Dataset
from airflow.operators.python import PythonOperator
from airflow.hooks.base import BaseHook
from datetime import datetime
import proxmoxer
import json

# 定義 Dataset
pve_metrics = Dataset('/opt/airflow/logs/pve_status.json')

def get_pve_usage():
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
       
       nodes_status = []
       for node in proxmox.nodes.get():
           node_info = {
               'node': node['node'],
               'cpu_usage': node['cpu'],
               'memory_usage': node['mem'] / node['maxmem'] * 100,
               'disk_usage': node['disk'] / node['maxdisk'] * 100,
               'guests': []
           }
           
           for vm in proxmox.nodes(node['node']).qemu.get():
               if 'status' in vm:
                   guest_info = {
                       'id': vm['vmid'],
                       'name': vm.get('name', ''),
                       'status': vm['status'],
                       'cpu': vm.get('cpu', 0),
                       'memory': vm.get('mem', 0)
                   }
                   node_info['guests'].append(guest_info)
           
           nodes_status.append(node_info)
       
       print("PVE Status:")
       print(json.dumps(nodes_status, indent=2))
       
       with open('/opt/airflow/logs/pve_status.json', 'w') as f:
           json.dump(nodes_status, f, indent=2)
           
   except Exception as e:
       print(f"Error: {str(e)}")

with DAG(
   'pve_resource_monitor',
   start_date=datetime(2024, 1, 1),
   schedule='*/2 * * * *',
   catchup=False,
   tags=['pve', 'monitor']
) as dag:
   
   monitor_task = PythonOperator(
       task_id='get_pve_usage',
       python_callable=get_pve_usage,
       outlets=[pve_metrics]  # 設定輸出 dataset
   )

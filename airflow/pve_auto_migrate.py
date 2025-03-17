# Jason Tools (www.jason.tools) - Jason Cheng (jason@jason.tools)
from airflow import DAG, Dataset
from airflow.operators.python import PythonOperator
from airflow.models import Variable
from airflow.hooks.base import BaseHook
from datetime import datetime
import json
import proxmoxer

pve_metrics = Dataset('/opt/airflow/logs/pve_status.json')

def get_running_migrations(proxmox):
   migration_count = 0
   try:
       for node in proxmox.nodes.get():
           node_name = node['node']
           tasks = proxmox.nodes(node_name).tasks.get()
           for task in tasks:
               if task['status'] == 'running' and 'migrate' in task.get('type', ''):
                   migration_count += 1
   except Exception as e:
       print(f"Error checking migrations: {str(e)}")
   return migration_count

def get_ha_groups():

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


   ha_resources = proxmox.cluster.ha.resources.get()
   ha_groups = {}
   
   try:
       for group in proxmox.cluster.ha.groups.get():
           ha_groups[group['group']] = {
               'nodes': group['nodes'].split(','),
               'members': []
           }
       
       for resource in ha_resources:
           if resource['type'] == 'vm':
               vmid = str(resource['sid']).split(':')[-1]
               if resource['group'] in ha_groups:
                   ha_groups[resource['group']]['members'].append(vmid)
                   
       print(f"HA groups and members: {json.dumps(ha_groups, indent=2)}")
   except Exception as e:
       print(f"Error getting HA info: {str(e)}")
   
   return ha_groups

def log_migration(context, vm_id, vm_name, source_node, target_node):
   timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
   logs = context['task_instance'].xcom_pull(key='migration_logs') or []
   logs.append({
       "timestamp": timestamp,
       "vm_id": vm_id,
       "vm_name": vm_name,
       "source": source_node,
       "target": target_node,
       "reason": "Auto-migration due to resource overload"
   })
   context['task_instance'].xcom_push(key='migration_logs', value=logs)

def check_and_migrate(**context):
   enable_migration = Variable.get("enable_pve_migration", default_var="false").lower() == "true"
   cpu_threshold = float(Variable.get("pve_cpu_threshold", default_var="80"))
   memory_threshold = float(Variable.get("pve_memory_threshold", default_var="80"))
   max_migrations = int(Variable.get("pve_max_migrations", default_var="2"))
   
   if not enable_migration:
       print("Migration is disabled")
       return
   
   try:
       with open('/opt/airflow/logs/pve_status.json', 'r') as f:
           current_data = json.load(f)
   except Exception as e:
       print(f"Cannot read metrics data: {str(e)}")
       return

   try:
       ha_groups = get_ha_groups()
   except Exception as e:
       print(f"Cannot get HA groups: {str(e)}")
       return


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

   current_migrations = get_running_migrations(proxmox)
   if current_migrations >= max_migrations:
       print(f"Current running migrations ({current_migrations}) reached limit ({max_migrations}), skipping")
       return

   max_allowed_new_migrations = max_migrations - current_migrations
   print(f"Currently {current_migrations} migrations running, can start {max_allowed_new_migrations} new migrations")

   prev_ti = context['task_instance'].get_previous_ti()
   history = {}
   if prev_ti:
       history = prev_ti.xcom_pull(key='usage_history') or {}

   updated_nodes = {}
   
   for node in current_data:
       migrations_count = 0
       node_name = node['node']
       if node_name not in history:
           history[node_name] = []

       cpu_usage = node['cpu_usage'] * 100
       memory_usage = node['memory_usage']
       is_overloaded = (cpu_usage > cpu_threshold or memory_usage > memory_threshold)
       
       if len(history[node_name]) >= 3:
           history[node_name] = history[node_name][-2:]
       history[node_name].append(is_overloaded)
       updated_nodes[node_name] = history[node_name]
       
       print(f"Node {node_name}:")
       print(f"- Current state: CPU {cpu_usage:.1f}%, Memory {memory_usage:.1f}%")
       print(f"- History: {history[node_name]}")
       
       if len(history[node_name]) == 3 and all(history[node_name]):
           print(f"Node {node_name} is overloaded for 3 consecutive checks")
           
           vms_to_migrate = [vm for vm in node['guests'] if vm['status'] == 'running']
           vms_to_migrate.sort(key=lambda x: x.get('memory', 0), reverse=True)
           
           current_cpu = cpu_usage
           current_memory = memory_usage
           target_nodes_full = False
           
           for vm in vms_to_migrate:
               if migrations_count >= max_allowed_new_migrations:
                   print(f"Reached maximum allowed new migrations limit ({max_allowed_new_migrations})")
                   break
                   
               if current_cpu <= cpu_threshold and current_memory <= memory_threshold:
                   print(f"Resource usage is now below threshold")
                   break
               
               vmid = str(vm['id'])
               vm_ha_group = None
               
               for group_name, group_info in ha_groups.items():
                   if vmid in group_info['members']:
                       vm_ha_group = group_name
                       allowed_nodes = group_info['nodes']
                       break
               
               if not vm_ha_group:
                   print(f"VM {vmid} is not HA managed, skipping")
                   continue
               
               try:
                   vm_status = proxmox.nodes(node_name).qemu(vmid).status.current.get()
                   if vm_status.get('lock'):
                       print(f"VM {vmid} is locked (reason: {vm_status['lock']}), skipping")
                       continue
                       
                   print(f"VM {vmid} ({vm.get('name', '')}) is in HA group {vm_ha_group}")
                   print(f"Allowed nodes: {allowed_nodes}")
                   
                   target_node = None
                   min_usage = float('inf')
                   
                   suitable_target_exists = False
                   for potential_node in current_data:
                       if (potential_node['node'] in allowed_nodes and 
                           potential_node['node'] != node_name):
                           potential_cpu = potential_node['cpu_usage'] * 100
                           potential_memory = potential_node['memory_usage']
                           if potential_cpu < cpu_threshold - 10 and potential_memory < memory_threshold - 10:
                               suitable_target_exists = True
                               usage = max(potential_cpu, potential_memory)
                               if usage < min_usage:
                                   min_usage = usage
                                   target_node = potential_node['node']
                   
                   if not suitable_target_exists:
                       print("No nodes have enough capacity for migration")
                       target_nodes_full = True
                       break
                   
                   if target_node:
                       print(f"Migrating VM {vmid} ({vm.get('name', '')}) from {node_name} to {target_node}")
                       try:
                           proxmox.nodes(node_name).qemu(vmid).migrate.post(
                               target=target_node,
                               online=1
                           )
                           log_migration(context, vmid, vm.get('name', ''), node_name, target_node)
                           migrations_count += 1
                           current_cpu -= vm.get('cpu', 0) * 100
                           current_memory -= vm.get('memory', 0)
                       except Exception as e:
                           print(f"Migration failed: {str(e)}")
                   else:
                       print(f"No suitable target node found for VM {vmid}")
                       
               except Exception as e:
                   print(f"Error processing VM {vmid}: {str(e)}")
                   continue
                   
           if target_nodes_full:
               print("Skipping all migrations due to insufficient capacity on target nodes")
               continue

   context['task_instance'].xcom_push(key='usage_history', value=updated_nodes)

with DAG(
   'pve_auto_migrate',
   start_date=datetime(2024, 1, 1),
   schedule=[pve_metrics],
   catchup=False,
   description='Auto migrate VMs when node resource usage is high',
   tags=['pve', 'migrate']
) as dag:
   
   migrate_task = PythonOperator(
       task_id='check_and_migrate',
       python_callable=check_and_migrate
   )

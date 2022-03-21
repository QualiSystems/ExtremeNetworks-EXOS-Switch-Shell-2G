try:
    from mock import patch, create_autospec
except:
    from unittest.mock import patch, create_autospec
from cloudshell.shell.core.driver_context import ResourceCommandContext, ResourceContextDetails, \
    ReservationContextDetails, ConnectivityContext
from driver import ExtremeosDriver as ShellDriver

set_vlan = "setVlan"

request1 = """{
  "driverRequest" : {
    "actions" : [{
      "connectionId" : "457238ad-4023-49cf-8943-219cb038c0dc",
      "connectionParams" : {
        "vlanId" : "75, 46-120, 130-131, 334",
        "mode" : "Trunk",
        "vlanServiceAttributes" : [{
          "attributeName" : "QnQ",
          "attributeValue" : "False",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "CTag",
          "attributeValue" : "",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Isolation Level",
          "attributeValue" : "Shared",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Access Mode",
          "attributeValue" : "Access",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "VLAN ID",
          "attributeValue" : "876",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Virtual Network",
          "attributeValue" : "876",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Pool Name",
          "attributeValue" : "",
          "type" : "vlanServiceAttribute"
        }
        ],
        "type" : "setVlanParameter"
      },
      "connectorAttributes" : [],
      "actionId" : "457238ad-4023-49cf-8943-219cb038c0dc_4244579e-bf6f-4d14-84f9-32d9cacaf9d9",
      "actionTarget" : {
        "fullName" : "Router/Chassis 0/GigabitEthernet0-2",
        "fullAddress" : "192.168.28.150/1/1/1/7",
        "type" : "actionTarget"
      },
      "customActionAttributes" : [],
      "type" : "removeVlan"
    }
    ]
  }
}"""

request2 = """{
  "driverRequest" : {
    "actions" : [{
      "connectionId" : "457238ad-4023-49cf-8943-219cb038c0dc",
      "connectionParams" : {
        "vlanId" : "75, 46-120, 130-131, 334",
        "mode" : "Trunk",
        "vlanServiceAttributes" : [{
          "attributeName" : "QnQ",
          "attributeValue" : "False",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "CTag",
          "attributeValue" : "",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Isolation Level",
          "attributeValue" : "Shared",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Access Mode",
          "attributeValue" : "Access",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "VLAN ID",
          "attributeValue" : "876",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Virtual Network",
          "attributeValue" : "876",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Pool Name",
          "attributeValue" : "",
          "type" : "vlanServiceAttribute"
        }
        ],
        "type" : "setVlanParameter"
      },
      "connectorAttributes" : [],
      "actionId" : "457238ad-4023-49cf-8943-219cb038c0dc_4244579e-bf6f-4d14-84f9-32d9cacaf9d9",
      "actionTarget" : {
        "fullName" : "Router/Chassis 1/GigabitEthernet0-1",
        "fullAddress" : "192.168.28.150/P26",
        "type" : "actionTarget"
      },
      "customActionAttributes" : [],
      "type" : "setVlan"
    }
    ]
  }
}"""

SHELL_NAME = ShellDriver.SHELL_NAME + "."
address = "192.168.105.92"
user = 'admin'
password = 'admin'

enable_password = 'admin'

# enable_password = 'cisco'
# enable_password = 'Password1'
# enable_password = 'Password2'
auth_key = 'h8WRxvHoWkmH8rLQz+Z/pg=='
api_port = 8029
# ro_community = "192.168.0.221.snmp"
ro_community = "public"
ShellDriver.SUPPORTED_OS = [".*"]

# context = ResourceCommandContext()
context = create_autospec(ResourceCommandContext)
context.resource = create_autospec(ResourceContextDetails)
context.resource.name = address
context.resource.fullname = 'Test Aireos'
context.resource.family = 'CS_Switch'
context.reservation = create_autospec(ReservationContextDetails)
context.reservation.reservation_id = 'test_id'
context.resource.attributes = {}
context.resource.id = ""
context.resource.attributes['{}User'.format(SHELL_NAME)] = user
context.resource.attributes['{}Password'.format(SHELL_NAME)] = password
context.resource.attributes['{}host'.format(SHELL_NAME)] = address
context.resource.attributes['{}Enable Password'.format(SHELL_NAME)] = enable_password
# context.resource.attributes['Port'] = port
# context.resource.attributes['Backup Location'] = 'tftp://172.25.10.96/AireOS_test'
# context.resource.attributes['{}Backup Location'.format(SHELL_NAME)] = 'ftp://junos:junos@192.168.85.47'
# context.resource.attributes['{}Backup Location'.format(SHELL_NAME)] = 'ftp://user:pass@172.29.128.11'
# context.resource.attributes['{}Backup Location'.format(SHELL_NAME)] = '172.29.128.16'
# context.resource.attributes['{}Backup Location'.format(SHELL_NAME)] = '172.29.128.20//ftp'
context.resource.attributes['{}Backup Location'.format(SHELL_NAME)] = '192.168.105.3/192.168.105.55-running-290620-100535'
context.resource.attributes['{}Backup Type'.format(SHELL_NAME)] = 'ftp'
context.resource.attributes['{}Backup User'.format(SHELL_NAME)] = 'test_user'
context.resource.attributes['{}Backup Password'.format(SHELL_NAME)] = 'test_password'
# context.resource.attributes['{}Backup User'.format(SHELL_NAME)] = 'gns3'
# context.resource.attributes['{}Backup Password'.format(SHELL_NAME)] = 'gns3'
context.resource.address = address

# todo AttributeError: Mock object has no attribute 'connectivity'
# context.connectivity = ConnectivityContext()
# context.connectivity.admin_auth_token = auth_key
# context.connectivity.server_address = '10.5.1.2'
# context.connectivity.cloudshell_api_port = api_port

import mock
context.connectivity = mock.MagicMock()
context.connectivity.admin_auth_token = 'Er4rWgbKv06-j3ZhUp9mEw2'
context.connectivity.server_address = '192.168.0.112'

# snmpwalk -v3  -l authPriv -u v3admin -a MD5 -A "v3adminauth"  -x DES -X "v3adminpriv"

context.resource.attributes['{}SNMP Version'.format(SHELL_NAME)] = 'v3'
# context.resource.attributes['{}SNMP Version'.format(SHELL_NAME)] = '3'
context.resource.attributes['{}SNMP Read Community'.format(SHELL_NAME)] = ro_community
context.resource.attributes['{}SNMP V3 User'.format(SHELL_NAME)] = 'v3admin2'
context.resource.attributes['{}SNMP V3 Password'.format(SHELL_NAME)] = 'v3adminauth'
context.resource.attributes['{}SNMP V3 Private Key'.format(SHELL_NAME)] = 'v3adminpriv'
context.resource.attributes['{}SNMP V3 Authentication Protocol'.format(SHELL_NAME)] = 'MD5'
context.resource.attributes['{}SNMP V3 Privacy Protocol'.format(SHELL_NAME)] = 'DES'
context.resource.attributes['{}CLI Connection Type'.format(SHELL_NAME)] = 'auto'

# configure snmpv3 add access snmpgroup sec-level priv read-view randomvvv write-view randomvvv
# configure snmpv3 add user snmpuser authentication md5 snmppassword privacy aes privkey111

context.resource.attributes['{}Enable SNMP'.format(SHELL_NAME)] = 'True'
context.resource.attributes['{}Disable SNMP'.format(SHELL_NAME)] = 'False'
context.resource.attributes['{}Sessions Concurrency Limit'.format(SHELL_NAME)] = '2'

# context.resource.attributes['{}Console Server IP Address'.format(SHELL_NAME)] = '192.168.26.111'
context.resource.attributes['{}Console User'.format(SHELL_NAME)] = ''
context.resource.attributes['{}Console Password'.format(SHELL_NAME)] = ''
context.resource.attributes['{}Console Port'.format(SHELL_NAME)] = 17016

if __name__ == '__main__':
    res = dict(context.resource.attributes)

    driver = ShellDriver()
    driver.initialize(context)

    with patch('driver.CloudShellSessionContext') as get_api:
        api = type('api', (object,),
                   {'DecryptPassword': lambda self, pw: type('Password', (object,), {'Value': pw})()})()
        # get_api.return_value = api

        get_api.return_value.get_api.return_value = api
        # driver.SUPPORTED_OS = "."

        response_autoload = driver.get_inventory(context)
        print('{}'.format(response_autoload))

        # response_save_scp = driver.save(context=context, folder_path="scp://gns3:gns3@192.168.105.2/config", configuration_type="running", vrf_management_name="")
        # response_save_tftp = driver.save(context=context, folder_path="tftp://192.168.105.3", configuration_type="startup", vrf_management_name="")
        # response_save_ftp = driver.save(context=context, folder_path="ftp://test_user:test_password@192.168.105.3", configuration_type="running", vrf_management_name="")
        # response_save_auto = driver.save(context=context, folder_path="", configuration_type="running", vrf_management_name="")
        # response_save_auto = driver.save(context=context, folder_path="flash:/", configuration_type="running", vrf_management_name="")

        # response_save = driver.save(context=context, folder_path="tftp://10.212.128.14/", configuration_type="Startup", vrf_management_name="")
        # driver.restore(context=context,
        #                path="tftp://10.212.128.5/192.168.105.92-running-060122-111631",
        #                configuration_type="running",
        #                restore_method="override",
        #                vrf_management_name="")

        # response_hlth_chk = driver.health_check(context=context)
        # response = driver.load_firmware(context=context, path="pp", vrf_management_name=None)
        # response_connect1_5 = driver.ApplyConnectivityChanges(context=context, request=request1_5)
        # response_connect = driver.ApplyConnectivityChanges(context=context, request=request2)
        # response_connect2 = driver.ApplyConnectivityChanges(context=context, request=request1)
        # response_run_cmd = driver.run_custom_command(context=context, custom_command="show ver")
        # response_run_cmd1 = driver.run_custom_config_command(context=context, custom_command="ip ssh version 2")
        # response_save_scp = driver.save(context=context, folder_path="scp://gns3:gns3@192.168.105.2/config", configuration_type="running", vrf_management_name="")
        # response_save_tftp = driver.save(context=context, folder_path="tftp://192.168.105.3", configuration_type="startup", vrf_management_name="")
        # response_save_ftp = driver.save(context=context, folder_path="ftp://test_user:test_password@192.168.105.3", configuration_type="running", vrf_management_name="")
        # response_save_auto = driver.save(context=context, folder_path="", configuration_type="running", vrf_management_name="")
        # response_save_auto = driver.save(context=context, folder_path="flash:/", configuration_type="running", vrf_management_name="")
        # response = driver.save(context=context, folder_path="ftp://test_user:test_password@192.168.42.102", configuration_type="running", vrf_management_name="")
        # response = driver.save(context=context,
        #                        # folder_path="",
        #                        folder_path="scp://gns3:gns3@192.168.1.39//ftp",
        #                        # folder_path="scp://gns3:gns3@172.29.128.20//ftp",
        #                        configuration_type="running", vrf_management_name="")
        # response = driver.save(context=context, folder_path="scp://test:test@172.29.128.18/d:/test", configuration_type="running", vrf_management_name="management")
        # response = driver.save(context=context, folder_path="ftp://gns3:gns3@172.29.128.20/ftp", configuration_type="startup", vrf_management_name="")
        # response = driver.save(context=context, folder_path="", configuration_type="startup")
        # driver.restore(context=context,
        #                path="scp://172.29.128.20//ftp/172.29.128.12-running-021118-153427",
        #                # path="scp://gns3:gns3@192.168.1.39//tmp/scp/" + response,
        #                configuration_type="running",
        #                restore_method="override",
        #                vrf_management_name="")
        # response_restore_tftp = driver.restore(context=context,
        #                           path="tftp://192.168.105.3/192.168.105.4-running-280620-115500",
        #                           configuration_type="startup",
        #                           restore_method="append",
        #                           vrf_management_name="")
        # response_restore_scp = driver.restore(context=context,
        #                           path="scp://gns3:gns3@192.168.105.2/config/192.168.105.4-running-280620-115443",
        #                           configuration_type="running",
        #                           restore_method="override",
        #                           vrf_management_name="")
        # response_restore_ftp = driver.restore(context=context,
        #                           path="ftp://192.168.105.3/192.168.105.4-running-280620-115500",
        #                           configuration_type="running",
        #                           restore_method="append",
        #                           vrf_management_name="")
        # response_restore_ftp1 = driver.restore(context=context,
        #                           path="ftp://test_user:test_password@192.168.105.3/192.168.105.4-running-280620-115500",
        #                           configuration_type="startup",
        #                           restore_method="append",
        #                           vrf_management_name="")
        # response_restore_ftp2 = driver.restore(context=context,
        #                           path="ftp://test_user@192.168.105.3/192.168.105.4-running-280620-115500",
        #                           configuration_type="running",
        #                           restore_method="override",
        #                           vrf_management_name="")
        # response_restore_auto = driver.restore(context=context,
        #                                       path="",
        #                                       configuration_type="running",
        #                                       restore_method="append",
        #                                       vrf_management_name="")

        # print(response)

        # from cloudshell.shell.core.session.logging_session import LoggingSessionContext
        # from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
        # from cloudshell.shell.standards.networking.resource_config import NetworkingResourceConfig

        # logger = LoggingSessionContext.get_logger_with_thread_id(context)
        # api = CloudShellSessionContext(context).get_api()
        # resource_config = NetworkingResourceConfig.from_context(
        #     shell_name=driver.SHELL_NAME,
        #     supported_os=driver.SUPPORTED_OS,
        #     context=context,
        #     api=api,
        # )
        # cli_handler = driver._cli.get_cli_handler(resource_config, logger)

        pass
        pass
        pass

        print("*" * 20, "FINISH", "*" * 20)

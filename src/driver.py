#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
import json

from cloudshell.shell.core.driver_context import InitCommandContext, ResourceCommandContext, AutoLoadResource, \
    AutoLoadAttribute, AutoLoadDetails, CancellationContext, ConnectivityContext, AutoLoadCommandContext, ResourceContextDetails
from cloudshell.shell.core.driver_utils import GlobalLock
from cloudshell.shell.core.interfaces.save_restore import OrchestrationSaveResult, OrchestrationSavedArtifact, \
    OrchestrationSavedArtifactInfo, OrchestrationRestoreRules
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
# from cloudshell.shell.flows.connectivity.models.connectivity_result import ConnectivitySuccessResponse
from cloudshell.shell.flows.connectivity.simple_flow import apply_connectivity_changes
from cloudshell.shell.standards.networking.driver_interface import NetworkingResourceDriverInterface
from cloudshell.shell.standards.networking.resource_config import (
    NetworkingResourceConfig,
)
from cloudshell.shell.core.session.logging_session import LoggingSessionContext
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
# from cloudshell.cli.service.cli import CLI
from cloudshell.cli.service.session_pool_manager import SessionPoolManager
from cloudshell.snmp.snmp_configurator import (
    EnableDisableSnmpConfigurator,
    EnableDisableSnmpFlowInterface,
)

from cloudshell.extremenetworks.flows.extremenetworks_load_firmware_flow import (
    ExtremenetworksLoadFirmwareFlow as FirmwareFlow,
)

from cloudshell.extremenetworks.flows.extremenetworks_state_flow import ExtremenetworksStateFlow as StateFlow
from cloudshell.extremenetworks.flows.extremenetworks_connectivity_flow import \
    ExtremenetworksConnectivityFlow as ConnectivityFlow

# from cloudshell..cisco.cli.cisco_cli_handler import CiscoCli
# from mock import MagicMock as ExtremeCli  # todo

from cloudshell.extremenetworks.flows.extremenetworks_run_command_flow import \
    ExtremenetworksRunCommandFlow as CommandFlow

from cloudshell.extremenetworks.cli.extreme_cli_handler import ExtremeCli
from cloudshell.extremenetworks.snmp.extremenetworks_snmp_handler import ExtremenetworksSnmpHandler
from cloudshell.extremenetworks.flows.extremenetworks_autoload_flow import \
    ExtremenetworksSnmpAutoloadFlow as AutoloadFlow
# from cloudshell.shell.flows.autoload.basic_flow import AbstractAutoloadFlow
from cloudshell.shell.standards.networking.autoload_model import NetworkingResourceModel
from cloudshell.extremenetworks.flows.extreme_configuration_flow import (
    ExtremeConfigurationFlow as ConfigurationFlow,
)

#from data_model import *  # run 'shellfoundry generate' to generate data model classes


class ExtremeosDriver(ResourceDriverInterface, NetworkingResourceDriverInterface, GlobalLock):
    SUPPORTED_OS = [r"[Ee]x?os"]
    SHELL_NAME = "Extremeos"
    """
    ResourceDriverInterface - describe all functionality/methods which should be implemented
                              for base abstract resource
    NetworkingResourceDriverInterface - describe all functionality/methods which should be implemented
                                        for network resource based on Networking Standard

    In case of building driver based on Quali Standards and using Quali packages you can simplify your work
    by importing functionality from cloudshell-shell-standards package:
    from cloudshell.shell.standards.networking.resource_config import NetworkingResourceConfig

    and organize working with network resource configuration as with object:
    resource_config = NetworkingResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                            supported_os=self.SUPPORTED_OS,
                                                            context=context)


    """
    def __init__(self):
        """ Constructor must be without arguments, it is created with reflection at run time """
        self._cli = None
        pass

    # def initialize(self, context):
    #     """
    #     Initialize the driver session, this function is called everytime a new instance of the driver is created
    #     This is a good place to load and cache the driver configuration, initiate sessions etc.
    #     :param InitCommandContext context: the context the command runs on
    #     """
    #     pass

    def initialize(self, context):
        """Initialize method.

        :type context: cloudshell.shell.core.context.driver_context.InitCommandContext
        """
        resource_config = NetworkingResourceConfig.from_context(
            self.SHELL_NAME, context
        )

        # session_pool_size = int(resource_config.sessions_concurrency_limit)
        # self._cli = CLI(
        #     SessionPoolManager(max_pool_size=session_pool_size, pool_timeout=100)
        # )

        self._cli = ExtremeCli(resource_config)
        # resource_config.sessions_concurrency_limit = 1  # todo
        pass

    # <editor-fold desc="Networking Standard Commands">
    @GlobalLock.lock
    def restore(self, context, path, configuration_type, restore_method, vrf_management_name):
        """
        Restores a configuration file
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str path: The path to the configuration file, including the configuration file name.
        :param str restore_method: Determines whether the restore should append or override the current configuration.
        :param str configuration_type: Specify whether the file should update the startup or running config.
        :param str vrf_management_name: Optional. Virtual routing and Forwarding management name
        """
        with LoggingSessionContext(context) as logger:
            api = CloudShellSessionContext(context).get_api()

            resource_config = NetworkingResourceConfig.from_context(
                shell_name=self.SHELL_NAME,
                supported_os=self.SUPPORTED_OS,
                context=context,
                api=api,
            )

            if not configuration_type:
                configuration_type = "running"

            if not restore_method:
                restore_method = "override"

            if not vrf_management_name:
                vrf_management_name = resource_config.vrf_management_name

            cli_handler = self._cli.get_cli_handler(resource_config, logger)
            configuration_flow = ConfigurationFlow(
                cli_handler=cli_handler, logger=logger, resource_config=resource_config
            )
            logger.info("Restore started")
            configuration_flow.restore(
                path=path,
                restore_method=restore_method,
                configuration_type=configuration_type,
                vrf_management_name=vrf_management_name,
            )
            logger.info("Restore completed")

    def save(self, context, folder_path, configuration_type, vrf_management_name):
        """
        Creates a configuration file and saves it to the provided destination
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str configuration_type: Specify whether the file should update the startup or running config. Value can one
        :param str folder_path: The path to the folder in which the configuration file will be saved.
        :param str vrf_management_name: Optional. Virtual routing and Forwarding management name
        :return The configuration file name.
        :rtype: str
        """

        """
        upload configuration
        upload configuration [hostname | ipaddress] filename {vr vr-name} {block-size block_size} """

        logger = LoggingSessionContext.get_logger_with_thread_id(context)
        api = CloudShellSessionContext(context).get_api()

        resource_config = NetworkingResourceConfig.from_context(
            shell_name=self.SHELL_NAME,
            supported_os=self.SUPPORTED_OS,
            context=context,
            api=api,
        )
        if not configuration_type:
            configuration_type = "running"

        if not vrf_management_name:
            vrf_management_name = resource_config.vrf_management_name  # todo what is that?

        cli_handler = self._cli.get_cli_handler(resource_config, logger)
        configuration_flow = ConfigurationFlow(
            cli_handler=cli_handler, logger=logger, resource_config=resource_config
        )
        logger.info("Save started")
        response = configuration_flow.save(
            folder_path=folder_path,
            configuration_type=configuration_type,
            vrf_management_name=vrf_management_name,
        )
        logger.info("Save completed")
        return response

    def run_custom_command(self, context, custom_command):
        logger = LoggingSessionContext.get_logger_with_thread_id(context)
        api = CloudShellSessionContext(context).get_api()
        resource_config = NetworkingResourceConfig.from_context(
            shell_name=self.SHELL_NAME,
            supported_os=self.SUPPORTED_OS,
            context=context,
            api=api,
        )
        cli_handler = self._cli.get_cli_handler(resource_config, logger)
        send_command_operations = CommandFlow(
            logger=logger, cli_configurator=cli_handler
        )
        response = send_command_operations.run_custom_command(
            custom_command=custom_command
        )
        logger.info(f"command [{custom_command}] returned output: [{response}]")         # todo debug print remove
        return response

    def run_custom_config_command(self, *args, **kwargs):
        return self.run_custom_command(self, *args, **kwargs)  # there's no enable mode on exos

    def shutdown(self, context):
        """Shutdown device.

        :param context: an object with all Resource Attributes inside
        :return:
        """
        logger = LoggingSessionContext.get_logger_with_thread_id(context)
        api = CloudShellSessionContext(context).get_api()

        resource_config = NetworkingResourceConfig.from_context(
            shell_name=self.SHELL_NAME,
            supported_os=self.SUPPORTED_OS,
            context=context,
            api=api,
        )

        cli_handler = self._cli.get_cli_handler(resource_config, logger)
        state_operations = StateFlow(
            logger=logger,
            api=api,
            resource_config=resource_config,
            cli_configurator=cli_handler,
        )

        return state_operations.shutdown()

    # ######### todo wip

    @GlobalLock.lock
    def load_firmware(self, context, path, vrf_management_name):
        # todo can't: unable to debug due to not being able to upload/download images idk why
        """Upload and updates firmware on the resource.

        :param context: an object with all Resource Attributes inside
        :param path: full path to firmware file, i.e. tftp://10.10.10.1/firmware.tar
        :param vrf_management_name: VRF management Name
        """
        logger = LoggingSessionContext.get_logger_with_thread_id(context)
        api = CloudShellSessionContext(context).get_api()

        resource_config = NetworkingResourceConfig.from_context(
            shell_name=self.SHELL_NAME,
            supported_os=self.SUPPORTED_OS,
            context=context,
            api=api,
        )

        if not vrf_management_name:
            vrf_management_name = resource_config.vrf_management_name

        cli_handler = self._cli.get_cli_handler(resource_config, logger)

        logger.info("Start Load Firmware")
        firmware_operations = FirmwareFlow(cli_handler=cli_handler, logger=logger)
        response = firmware_operations.load_firmware(
            path=path, vrf_management_name=vrf_management_name
        )
        logger.info("Finish Load Firmware: {}".format(response))

    # </editor-fold>

    # <editor-fold desc="Orchestration Save and Restore Standard">
    def orchestration_save(self, context, cancellation_context, mode, custom_params):
        """
        Saves the Shell state and returns a description of the saved artifacts and information
        This command is intended for API use only by sandbox orchestration scripts to implement
        a save and restore workflow
        :param ResourceCommandContext context: the context object containing resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str mode: Snapshot save mode, can be one of two values 'shallow' (default) or 'deep'
        :param str custom_params: Set of custom parameters for the save operation
        :return: SavedResults serialized as JSON
        :rtype: OrchestrationSaveResult
        """

        # See below an example implementation, here we use jsonpickle for serialization,
        # to use this sample, you'll need to add jsonpickle to your requirements.txt file
        # The JSON schema is defined at: https://github.com/QualiSystems/sandbox_orchestration_standard/blob/master/save%20%26%20restore/saved_artifact_info.schema.json
        # You can find more information and examples examples in the spec document at https://github.com/QualiSystems/sandbox_orchestration_standard/blob/master/save%20%26%20restore/save%20%26%20restore%20standard.md
        '''
        # By convention, all dates should be UTC
        created_date = datetime.datetime.utcnow()

        # This can be any unique identifier which can later be used to retrieve the artifact
        # such as filepath etc.

        # By convention, all dates should be UTC
        created_date = datetime.datetime.utcnow()

        # This can be any unique identifier which can later be used to retrieve the artifact
        # such as filepath etc.
        identifier = created_date.strftime('%y_%m_%d %H_%M_%S_%f')

        orchestration_saved_artifact = OrchestrationSavedArtifact('REPLACE_WITH_ARTIFACT_TYPE', identifier)

        saved_artifacts_info = OrchestrationSavedArtifactInfo(
            resource_name="some_resource",
            created_date=created_date,
            restore_rules=OrchestrationRestoreRules(requires_same_resource=True),
            saved_artifact=orchestration_saved_artifact)

        return OrchestrationSaveResult(saved_artifacts_info)
        '''
        pass

    def orchestration_restore(self, context, cancellation_context, saved_artifact_info, custom_params):
        """
        Restores a saved artifact previously saved by this Shell driver using the orchestration_save function
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str saved_artifact_info: A JSON string representing the state to restore including saved artifacts and info
        :param str custom_params: Set of custom parameters for the restore operation
        :return: None
        """
        '''
        # The saved_details JSON will be defined according to the JSON Schema and is the same object returned via the
        # orchestration save function.
        # Example input:
        # {
        #     "saved_artifact": {
        #      "artifact_type": "REPLACE_WITH_ARTIFACT_TYPE",
        #      "identifier": "16_08_09 11_21_35_657000"
        #     },
        #     "resource_name": "some_resource",
        #     "restore_rules": {
        #      "requires_same_resource": true
        #     },
        #     "created_date": "2016-08-09T11:21:35.657000"
        #    }

        # The example code below just parses and prints the saved artifact identifier
        saved_details_object = json.loads(saved_details)
        return saved_details_object[u'saved_artifact'][u'identifier']
        '''
        pass

    # </editor-fold>

    # <editor-fold desc="Connectivity Provider Interface (Optional)">

    # The ApplyConnectivityChanges function is intended to be used for using switches as connectivity providers
    # for other devices. If the Switch shell is intended to be used a DUT only there is no need to implement it

    def ApplyConnectivityChanges(self, context, request):
        """
        Create vlan and add or remove it to/from network interface.

        :param context: an object with all Resource Attributes inside
        :param str request: request json
        :return:
        """
        logger = LoggingSessionContext.get_logger_with_thread_id(context)
        api = CloudShellSessionContext(context).get_api()

        resource_config = NetworkingResourceConfig.from_context(
            shell_name=self.SHELL_NAME,
            supported_os=self.SUPPORTED_OS,
            context=context,
            api=api,
        )

        cli_handler = self._cli.get_cli_handler(resource_config, logger)
        connectivity_operations = ConnectivityFlow(
            logger=logger,
            cli_handler=cli_handler,
            support_multi_vlan_str=True,
            support_vlan_range_str=True,
        )
        logger.info("Start applying connectivity changes.")
        # todo debug line remove later
        logger.debug("*** xxx ***")
        logger.debug(request)
        logger.debug(request.__dict__)
        logger.debug("*** xxx ***")
        result = connectivity_operations.apply_connectivity_changes(request=request)
        logger.info("Apply Connectivity changes completed")
        return result

    # </editor-fold>

    # <editor-fold desc="Discovery">

    def get_inventory(self, context):
        """
        Discovers the resource structure and attributes.
        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """

        # See below some example code demonstrating how to return the resource structure and attributes
        # In real life, this code will be preceded by SNMP/other calls to the resource details and will not be static
        # run 'shellfoundry generate' in order to create classes that represent your data model

        '''
        resource = Extremeos.create_from_context(context)
        resource.vendor = 'specify the shell vendor'
        resource.model = 'specify the shell model'

        chassis1 = GenericChassis('Chassis 1')
        chassis1.model = 'WS-X4232-GB-RJ'
        chassis1.serial_number = 'JAE053002JD'
        resource.add_sub_resource('1', chassis1)

        module1 = GenericModule('Module 1')
        module1.model = 'WS-X5561-GB-AB'
        module1.serial_number = 'TGA053972JD'
        chassis1.add_sub_resource('1', module1)

        port1 = GenericPort('Port 1')
        port1.mac_address = 'fe80::e10c:f055:f7f1:bb7t16'
        port1.ipv4_address = '192.168.10.7'
        module1.add_sub_resource('1', port1)

        return resource.create_autoload_details()
        '''
        # return AutoLoadDetails([], [])

        with LoggingSessionContext(context) as logger:

            api = CloudShellSessionContext(context).get_api()
            logger.info('start get_inventory method')

            resource_config = NetworkingResourceConfig.from_context(
                self.SHELL_NAME, context, api, self.SUPPORTED_OS
            )

            cli_handler = self._cli.get_cli_handler(resource_config, logger)
            # cli_handler = mock.MagicMock()
            # snmp_handler = SNMPHandler(resource_config, logger, cli_handler)
            snmp_handler = ExtremenetworksSnmpHandler(resource_config, logger, cli_handler)

            autoload_operations = AutoloadFlow(logger=logger, snmp_handler=snmp_handler)
            logger.info("Autoload started")
            resource_model = NetworkingResourceModel(
                resource_config.name,
                resource_config.shell_name,
                resource_config.family_name,
            )

            response = autoload_operations.discover(
                resource_config.supported_os, resource_model
            )
            logger.info("Autoload completed")
            return response

    # cisco NXOS example
    '''
            with LoggingSessionContext(context) as logger:
            logger.info("Starting 'Autoload' command ...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = NetworkingResourceConfig.from_context(
                shell_name=self.SHELL_NAME,
                supported_os=self.SUPPORTED_OS,
                context=context,
                api=api,
            )
            cli_handler = self._cli.get_cli_handler(resource_config, logger)
            snmp_handler = CiscoSnmpHandler(resource_config, logger, cli_handler)
            autoload_operations = CiscoSnmpAutoloadFlow(
                logger=logger, snmp_handler=snmp_handler
            )

            resource_model = NetworkingResourceModel(
                resource_config.name,
                resource_config.shell_name,
                resource_config.family_name,
            )

            response = autoload_operations.discover(
                resource_config.supported_os, resource_model
            )
            logger.info("'Autoload' command completed")

            return response
    '''

    #cisco ios example
    '''
        logger = LoggingSessionContext.get_logger_with_thread_id(context)
        api = CloudShellSessionContext(context).get_api()

        resource_config = NetworkingResourceConfig.from_context(
            shell_name=self.SHELL_NAME,
            supported_os=self.SUPPORTED_OS,
            context=context,
            api=api,
        )
        cli_handler = self._cli.get_cli_handler(resource_config, logger)
        snmp_handler = SNMPHandler(resource_config, logger, cli_handler)

        autoload_operations = AutoloadFlow(logger=logger, snmp_handler=snmp_handler)
        logger.info("Autoload started")
        resource_model = NetworkingResourceModel(
            resource_config.name,
            resource_config.shell_name,
            resource_config.family_name,
        )

        response = autoload_operations.discover(
            resource_config.supported_os, resource_model
        )
        logger.info("Autoload completed")
        return response
    '''


    # </editor-fold>

    # <editor-fold desc="Health Check">

    def health_check(self, context):
        logger = LoggingSessionContext.get_logger_with_thread_id(context)
        api = CloudShellSessionContext(context).get_api()

        resource_config = NetworkingResourceConfig.from_context(
            shell_name=self.SHELL_NAME,
            supported_os=self.SUPPORTED_OS,
            context=context,
            api=api,
        )
        cli_handler = self._cli.get_cli_handler(resource_config, logger)

        state_operations = StateFlow(
            logger=logger,
            api=api,
            resource_config=resource_config,
            cli_configurator=cli_handler,
        )
        return state_operations.health_check()

    # </editor-fold>

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass


if __name__ == "__main__":

    import mock
    from cloudshell.shell.core.driver_context import CancellationContext


    ''' resource_config from live server:
    {'attributes': 
    {'CS_Switch.OS Version': '', 'CS_Switch.System Name': '', 'CS_Switch.Vendor': '', 'CS_Switch.Contact Name': '', 
    'CS_Switch.Location': '', 'CS_Switch.Model': '', 'CS_Switch.Model Name': '', 'Extremeos.VRF Management Name': '', 
    'Extremeos.User': 'admin', 'Extremeos.Password': 'DxTbqlSgAVPmrDLlHvJrsA==', 
    'Extremeos.Enable Password': '3M3u7nkDzxWb0aJ/IZYeWw==', 'Extremeos.Power Management': 'True', 
    'Extremeos.Sessions Concurrency Limit': '1', 'Extremeos.SNMP Read Community': '3M3u7nkDzxWb0aJ/IZYeWw==', 
    'Extremeos.SNMP Write Community': '3M3u7nkDzxWb0aJ/IZYeWw==', 'Extremeos.SNMP V3 User': '', 
    'Extremeos.SNMP V3 Password': '3M3u7nkDzxWb0aJ/IZYeWw==', 'Extremeos.SNMP V3 Private Key': '', 
    'Extremeos.SNMP V3 Authentication Protocol': 'No Authentication Protocol', 
    'Extremeos.SNMP V3 Privacy Protocol': 'No Privacy Protocol', 'Extremeos.SNMP Version': '', 
    'Extremeos.Enable SNMP': 'True', 'Extremeos.Disable SNMP': 'False', 'Extremeos.Console Server IP Address': '', 
    'Extremeos.Console User': '', 'Extremeos.Console Port': '0', 
    'Extremeos.Console Password': '3M3u7nkDzxWb0aJ/IZYeWw==', 'Extremeos.CLI Connection Type': 'Auto', 
    'Extremeos.CLI TCP Port': '0', 'Extremeos.Backup Location': '', 'Extremeos.Backup Type': 'File System', 
    'Extremeos.Backup User': '', 'Extremeos.Backup Password': '3M3u7nkDzxWb0aJ/IZYeWw==', 
    'Execution Server Selector': ''}, 
    'shell_name': 'Extreme Networks Extremexos idk idk', 'name': 'exos', 'supported_os': ['[Ee]x?os'], 
    'fullname': 'exos', 'address': '192.168.105.92', 'family_name': 'CS_Switch', 
    'namespace_prefix': 'Extreme Networks Extremexos idk idk', 
    'api': <cloudshell.api.cloudshell_api.CloudShellAPISession object at 0x02197C50>, 
    'cs_resource_id': '6637e24c-cf50-4d0b-a348-fa6e3a0c28e1'}
    '''

    cancellation_context = mock.create_autospec(CancellationContext)
    # context = mock.create_autospec(ResourceCommandContext)
    context = mock.create_autospec(AutoLoadCommandContext)
    # context.resource = mock.MagicMock()
    context.resource = mock.create_autospec(ResourceContextDetails)
    context.resource.name = 'dummy name'
    context.resource.fullname = 'dummy full name'
    context.resource.family = 'CS_Switch'


    shell_name = "Extremeos"
    SHELL_NAME = "{}.".format(shell_name)

    context.reservation = mock.MagicMock()
    context.connectivity = mock.MagicMock()
    # context.connectivity = ConnectivityContext()  # requires args
    # context.connectivity.admin_auth_token = ?
    context.connectivity.admin_auth_token = 'Er4rWgbKv06-j3ZhUp9mEw2'
    # context.connectivity.cloudshell_api_port = api_port
    context.connectivity.server_address = '192.168.0.112'  # -
    # context.reservation.reservation_id = "<RESERVATION_ID>"
    context.resource.address = "192.168.105.92"
    context.resource.name = "exos"
    context.resource.id = "res id"
    context.resource.attributes = dict()
    context.resource.attributes["{}User".format(SHELL_NAME)] = "admin"
    context.resource.attributes["{}Password".format(SHELL_NAME)] = "admin"
    context.resource.attributes["{}SNMP Read Community".format(SHELL_NAME)] = "ofunbsdojgbdfougdf"
    # context.resource.attributes['{}host'.format(SHELL_NAME)] = '192.168.0.112'
    context.resource.attributes['{}Enable Password'.format(SHELL_NAME)] = 'admin'
    context.resource.attributes['{}SNMP V3 Password'.format(SHELL_NAME)] = 'password'
    context.resource.attributes['{}Enable SNMP'.format(SHELL_NAME)] = 'False'
    context.resource.attributes['{}SNMP Version'.format(SHELL_NAME)] = 'v3'
    # context.resource.attributes['{}SNMP Read Community'.format(SHELL_NAME)] = ro_community
    context.resource.attributes['{}SNMP V3 User'.format(SHELL_NAME)] = 'user'
    context.resource.attributes['{}SNMP V3 Password'.format(SHELL_NAME)] = 'password'
    context.resource.attributes['{}SNMP V3 Private Key'.format(SHELL_NAME)] = 'oufhsdfougbdfougf'
    context.resource.attributes['{}SNMP V3 Authentication Protocol'.format(SHELL_NAME)] = 'MD5'
    context.resource.attributes['{}SNMP V3 Privacy Protocol'.format(SHELL_NAME)] = 'No Privacy Protocol'
    context.resource.attributes['{}CLI Connection Type'.format(SHELL_NAME)] = 'auto'
    context.resource.attributes['{}Enable SNMP'.format(SHELL_NAME)] = 'True'
    context.resource.attributes['{}Disable SNMP'.format(SHELL_NAME)] = 'False'
    # context.resource.attributes['{}Sessions Concurrency Limit'.format(SHELL_NAME)] = '1'
    # context.resource.attributes['{}Console Server IP Address'.format(SHELL_NAME)] = '192.168.26.111'
    context.resource.attributes['{}Console User'.format(SHELL_NAME)] = ''
    context.resource.attributes['{}Console Password'.format(SHELL_NAME)] = ''
    context.resource.attributes['{}Console Port'.format(SHELL_NAME)] = 17016


    driver = ExtremeosDriver()

    # print driver.run_custom_command(context, custom_command="sh run", cancellation_context=cancellation_context)
    driver.initialize(context)
    result = driver.get_inventory(context)



    print("done")

"""Generic TAXII1 connector. """

import os
import time
import json
from datetime import datetime, timedelta
from stix.core.stix_package import STIXPackage
import stix.report
from stix2elevator import elevate
from stix2elevator.options import initialize_options
import yaml
import pytz
from cabby import create_client
from cabby.exceptions import HTTPError
from requests.exceptions import ConnectionError
from io import BytesIO, StringIO
from pycti import OpenCTIConnectorHelper, get_config_variable
from mixbox.namespaces import Namespace, register_namespace

#import overrides


class Taxii1Connector:
    """Connector object"""

    def __init__(self):
        """Read in config variables"""

        config_file_path = os.path.dirname(os.path.abspath(__file__))
        config_file_path += "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        username = get_config_variable(
            "TAXII1_USERNAME", ["taxii1", "username"], config
        )
        password = get_config_variable(
            "TAXII1_PASSWORD", ["taxii1", "password"], config
        )
        self.discovery_url = get_config_variable(
            "TAXII1_DISCOVERY_URL", ["taxii1", "discovery_url"], config
        )
        self.verify_ssl = get_config_variable(
            "VERIFY_SSL", ["taxii1", "verify_ssl"], config, default=True
        )

        # if V11 flag set to true
        if get_config_variable("TAXII1_V11", ["taxii1", "v1.1"], config, default=True):
            self.client = create_client(discovery_url=self.discovery_url, version='1.1')
        else:
            self.client = create_client(discovery_url=self.discovery_url, version='1.0')

        self.client.set_auth(username=username, password=password)

        self.collections = get_config_variable(
            "TAXII1_COLLECTIONS", ["taxii1", "collections"], config
        ).split(",")

        self.initial_history = get_config_variable(
            "TAXII1_INITIAL_HISTORY", ["taxii1", "initial_history"], config, True
        )

        self.per_request = get_config_variable(
            "TAXII1_PER_REQUEST", ["taxii1", "per_request"], config, True
        )

        self.interval = get_config_variable(
            "TAXII1_INTERVAL", ["taxii1", "interval"], config, True, 1
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        self.create_report = get_config_variable(
            "TAXII1_CREATE_REPORT", ["taxii1", "create_report"], config, default=True
        )

        # Initialize STIX elevator options
        initialize_options(options={"spec_version": "2.1",
                                    "markings_allowed": "ISAMarkingsAssertion,ISAMarkings",
                                    "silent": True})

        # Register namespaces used by some threat intel sources
        register_namespace(Namespace("http://xml/metadataSharing.xsd", "metadataSharing", "http://grouper.ieee.org/groups/malware/malwg/Schema1.2/metadataSharing.xsd"))

    def get_interval(self):
        """Converts interval hours to seconds"""
        return int(self.interval) * 3600

    @property
    def first_run(self):
        """Checks if connector has run before"""
        current_state = self.helper.get_state()
        return current_state is None or "last_run" not in current_state

    def get_server_collections(self):
        server_collections = None
        # Get TAXII server collection management service URL
        try:
            for service in self.client.discover_services():
                if service.type == "COLLECTION_MANAGEMENT":
                    # Get list of available collections from TAXII server collection management service
                    server_collections = self.client.get_collections(uri=service.address)
        except (ConnectionError, HTTPError) as err:
            self.helper.log_error("Failed to connect to discovery URL {}".format(self.discovery_url))
            self.helper.log_debug(err)
            return

        return server_collections

    def elevate_package(self, package):
        if self.create_report:
            # Parse package XML as STIX1 object
            package = STIXPackage.from_xml(StringIO(package))
            if package.stix_header.title and package.reports is None:
                report = stix.report.Report(header=stix.report.Header(title=package.stix_header.title,
                                                            description=package.stix_header.description or None,
                                                            intents=package.stix_header.package_intents),
                                            campaigns=stix.report.Campaigns(package.campaigns) or None,
                                            courses_of_action=stix.report.CoursesOfAction(package.courses_of_action) or None,
                                            exploit_targets=stix.report.ExploitTargets(package.exploit_targets) or None,
                                            incidents=stix.report.Incidents(package.incidents) or None,
                                            indicators=stix.report.Indicators(package.indicators) or None,
                                            threat_actors=stix.report.ThreatActors(package.threat_actors) or None,
                                            ttps=stix.report.TTPs(package.ttps) or None)
                package.add(report)

        package = elevate(package.to_xml())

        return package

    def send_to_server(self, bundle):
        """
        Sends a STIX2 bundle to OpenCTI Server
        Args:
            bundle (list(dict)): STIX2 bundle represented as a list of dicts
        """
        if "objects" in bundle:
            self.helper.log_info(
                f"Sending Bundle to server with " f'{len(bundle["objects"])} objects'
            )
            try:
                self.helper.send_stix2_bundle(json.dumps(bundle),
                                              update = self.update_existing_data)
            except Exception as e:
                self.helper.log_error(str(e))

    def poll_collection(self, collection, earliest_time=None):
        for polling_service in collection.polling_services:
            packages = None
            self.helper.log_debug("Polling collection '{}'".format(collection.name))
            try:
                content_blocks = self.client.poll(collection_name=collection.name,
                                                    uri=polling_service.address,
                                                    begin_date=earliest_time)
                with BytesIO() as data:
                    for block in content_blocks:
                        data.write(block.content)
                    data.seek(0)
                    delim = "<stix:STIX_Package"
                    packages = [delim + e for e in data.read().decode().split(delim) if e]
                    #packages.pop(0)
            except (ConnectionError, HTTPError) as err:
                self.helper.log_error("Failed to poll collection {}".format(collection.name))
                self.helper.log_debug(err)
                continue
            
            for package in packages:
                package = STIXPackage.from_xml(StringIO(package))
                package = self.elvate_package(package)
                
                self.send_to_server(json.loads(package))

    def run(self):
        """Run connector on a schedule"""
        while True:
            timestamp = int(time.time())

            if self.first_run:
                self.helper.log_info("Connector has never run")
            else:
                last_run = datetime.utcfromtimestamp(
                    self.helper.get_state()["last_run"]
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info("Connector last run: " + last_run)

            

            if self.first_run:
                lookback = self.initial_history or None
            else:
                lookback = self.interval
            if lookback:
                earliest = datetime.now(tz=datetime.now().astimezone().tzinfo) - timedelta(hours=lookback)
                
            for collection in self.get_server_collections():
                if '*' in self.collections or collection.name in self.collections:
                    self.poll_collection(collection, earliest_time=earliest)
            
            self.helper.log_info(
                f"Run Complete. Sleeping until next run in " f"{self.interval} hours"
            )
            self.helper.set_state({"last_run": timestamp})
            time.sleep(self.get_interval())


if __name__ == "__main__":
    try:
        CONNECTOR = Taxii1Connector()
        CONNECTOR.run()
    except Exception as e:
        raise e
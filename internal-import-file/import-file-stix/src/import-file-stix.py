import os
import yaml
import time
from typing import List, Dict
from stix2 import Report, Bundle, parse
from stix2elevator import elevate
from stix2elevator.options import initialize_options
from stix.core import STIXPackage
import stix.report as stix1_report
from pycti import OpenCTIConnectorHelper, get_config_variable
from io import BytesIO


class ImportFileStix:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.create_report = get_config_variable(
            "IMPORT_STIX_CREATE_REPORT",
            ["import_stix", "create_report"],
            config,
        )

    def _process_message(self, data: Dict) -> str:
        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch
        self.helper.log_info(f"Importing the file {file_uri}")

        file_content = self.helper.api.fetch_opencti_file(file_uri, binary=True)
        if data["file_mime"] == "text/xml":
            self.helper.log_debug("Stix1 file. Attempting conversion")
            if self.create_report:
                package = STIXPackage.from_xml(BytesIO(file_content))
                if package.stix_header.title and package.reports is None:
                    report = stix1_report.Report(header=stix1_report.Header(title=package.stix_header.title,
                                                                            description=package.stix_header.description or None,
                                                                            intents=package.stix_header.package_intents),
                                                campaigns=stix1_report.Campaigns(package.campaigns) or None,
                                                courses_of_action=stix1_report.CoursesOfAction(package.courses_of_action) or None,
                                                exploit_targets=stix1_report.ExploitTargets(package.exploit_targets) or None,
                                                incidents=stix1_report.Incidents(package.incidents) or None,
                                                indicators=stix1_report.Indicators(package.indicators) or None,
                                                threat_actors=stix1_report.ThreatActors(package.threat_actors) or None,
                                                ttps=stix1_report.TTPs(package.ttps) or None)

                    package.add(report)
                    file_content=package.to_xml()

            initialize_options()
            file_content = elevate(file_content)

        entity_id = data.get("entity_id", None)
        if entity_id:
            self.helper.log_debug("Contextual import.")

            bundle = parse(file_content)["objects"]

            if self._contains_report(bundle):
                self.helper.log_debug("Bundle contains report.")
            else:
                self.helper.log_debug("No Report in Stix file. Updating current report")
                bundle = self._update_report(bundle, entity_id)

            file_content = Bundle(objects=bundle).serialize()

        bundles_sent = self.helper.send_stix2_bundle(file_content)
        return "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"

    # Start the main loop
    def start(self) -> None:
        self.helper.listen(self._process_message)

    @staticmethod
    def _contains_report(bundle: List) -> bool:
        for elem in bundle:
            if type(elem) == Report:
                return True
        return False

    def _update_report(self, bundle: List, entity_id: int) -> List:
        report = self.helper.api.report.read(id=entity_id)
        # The entity_id can be any SDO
        if report:
            report = Report(
                id=report["standard_id"],
                name=report["name"],
                description=report["description"],
                published=self.helper.api.stix2.format_date(report["created"]),
                report_types=report["report_types"],
                object_refs=bundle,
            )
            bundle.append(report)
        return bundle


if __name__ == "__main__":
    try:
        connectorImportFileStix = ImportFileStix()
        connectorImportFileStix.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)

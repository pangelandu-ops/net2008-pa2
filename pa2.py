
# Name: Pierre Landu
# StuID: 041182810

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml


class AuditError(Exception):
    """Represents an error while reading audit input files  """


class Device:
    """Stores  information about one network device """

    def __init__(self, element):
        """Extract device details from an XML element """
        self.id = element.get("id")

        self.role = element.get("role")

        self.os = element.get("os")

        owner = element.find("owner")

        self.owner = owner.text.strip() if owner is not None and owner.text else ""

        self.interface_statuses = [
            interface.get("status")
            for interface in element.findall("interface")
        ] 

    def count_down_interfaces(self):
        """Count the interfaces that are down """
        return self.interface_statuses.count("down")

    def count_interfaces(self):
        """Count up, down, and other interface status's """
        counts = {"up": 0, "down": 0, "other": 0}

        for status in self.interface_statuses:
            if status == "up":
                counts["up"] += 1
            elif status == "down":
                counts["down"] += 1
            else:
                counts["other"] += 1

        return counts


def load_inventory(filename):
    """Read and parse the XML inventory file """
    try:
        tree = ET.parse(filename)
        return tree.getroot()
    except (OSError, ET.ParseError) as error:
        raise AuditError(f"{filename}: {error}") from error


def load_policy(filename):
    """Read and validate the YAML policy file """
    try:
        with open(filename, "r", encoding="utf-8") as file:
            content = file.read()

        if content.strip() == "":
            return {}

        policy = yaml.safe_load(content)

        if not isinstance(policy, dict):
            raise AuditError(f"{filename}: policy must be a YAML map")

        return policy

    except OSError as error:
        raise AuditError(f"{filename}: {error}") from error
    except yaml.YAMLError as error:
        raise AuditError(f"{filename}: invalid YAML: {error}") from error


def version_is_lower(found, required):
    """Compare software versions numericly part by part """
    found_parts = tuple(int(part) for part in found.split("."))
    required_parts = tuple(int(part) for part in required.split("."))

    length = max(len(found_parts), len(required_parts))

    found_parts += (0,) * (length - len(found_parts))
    required_parts += (0,) * (length - len(required_parts))

    return found_parts < required_parts


def main():
    """Read the inventory and policy thn audit every device """
    if len(sys.argv) != 3:
        print("usage: python pa2.py   DEVICES.xml  POLICY.yaml")
        return 2

    xml_file = Path(sys.argv[1])
  
    yaml_file = Path(sys.argv[2])

    try: 
        root = load_inventory(xml_file)
            
        policy = load_policy(yaml_file)

        devices = []
        skipped_devices = 0
        roles = {}
        interfaces = {"up": 0, "down": 0, "other": 0}

        for element in root.findall("device"):
            device = Device(element)

            if device.id is None:
                skipped_devices += 1
                continue

            devices.append(device)

            roles[device.role] = roles.get(device.role, 0) +  1

            device_interfaces = device.count_interfaces()

            for status in interfaces:
                interfaces[status] += device_interfaces[status]

        violations = []

        compliant = []

        min_os = policy.get("min_os", {})
        if not isinstance(min_os, dict):
            min_os = {}

        for device in devices:
            device_violations = []

            if "min_os" in policy:
                if device.role not in min_os:
                    device_violations.append({
                        "device": device.id,
                        "type": "unknown_role",
                        "role": device.role
                    })
                elif device.os is not None and version_is_lower(
                    device.os, min_os[device.role]
                ):
                    device_violations.append({
                        "device": device.id,
                        "type": "os_outdated",
                        "found": device.os,
                        "required": min_os[device.role]
                    })

            if policy.get("require_owner") is True and not device.owner:
                device_violations.append({
                    "device": device.id,
                    "type": "missing_owner"
                })

            down_count = device.count_down_interfaces()

            if (
                "max_down_interfaces" in policy
                and down_count > policy["max_down_interfaces"]
            ):
                device_violations.append({
                    "device": device.id,
                    "type": "too_many_down",
                    "down": down_count
                })

            if device_violations:
                violations.extend(device_violations)
            else:
                compliant.append(device.id)

        report = {
            "site": root.get("site"),
            "total_devices": len(devices),
            "skipped_devices": skipped_devices,
            "roles": roles,
            "interfaces": interfaces,
            "violations": violations,
            "compliant": sorted(compliant)
        }

        try:
            with open("audit.json", "w", encoding="utf-8") as file:
                json.dump(report, file, indent=4)
        except OSError as error:
            raise AuditError(f"audit.json: {error}") from error

        print("Audit complete!")
        print("Total devices:", report["total_devices"])
        print("Skipped devices:", report["skipped_devices"])
        print("Violations:", len(report["violations"]))
        print("Report saved to audit.json")

        return 0

    except AuditError as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

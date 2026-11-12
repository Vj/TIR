# engines/dynamic/agent_navigator.py
import os
import time
import json
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

class AgentNavigator:
    def __init__(self, package_name: str, device_id: Optional[str] = None, evidence_dir: str = "reporting/evidence"):
        self.package_name = package_name
        self.device_id = device_id
        self.evidence_dir = os.path.abspath(evidence_dir)
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.execution_path: List[Dict[str, Any]] = []

    def _adb_exec(self, cmd_args: List[str]) -> str:
        base = ["adb"]
        if self.device_id:
            base.extend(["-s", self.device_id])
        base.extend(cmd_args)
        try:
            res = subprocess.run(base, capture_output=True, text=True, encoding="utf-8",errors="replace",timeout=15)
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def dump_interactive_ui_nodes(self) -> str:
        """
        Dumps the UI hierarchy via uiautomator and extracts clickable, editable,
        or sensitive fields so the LLM knows what actions it can take.
        """
        remote_xml = "/data/local/tmp/window_dump.xml"
        self._adb_exec(["shell", "uiautomator", "dump", remote_xml])
        local_xml_content = self._adb_exec(["shell", "cat", remote_xml])
        self._adb_exec(["shell", "rm", "-f", remote_xml])

        if not local_xml_content or "hierarchy" not in local_xml_content:
            return json.dumps({"error": "Failed to dump UI hierarchy or screen is non-interactive."})

        nodes = []
        try:
            root = ET.fromstring(local_xml_content)
            for node in root.iter("node"):
                attrib = node.attrib
                is_clickable = attrib.get("clickable") == "true"
                is_editable = "EditText" in attrib.get("class", "")
                text = attrib.get("text", "")
                content_desc = attrib.get("content-desc", "")
                res_id = attrib.get("resource-id", "")
                bounds = attrib.get("bounds", "")

                if is_clickable or is_editable or text or content_desc:
                    # Calculate center coordinates for clicking
                    # bounds format: [x1,y1][x2,y2]
                    coords = self._parse_bounds_center(bounds)
                    nodes.append({
                        "class": attrib.get("class", "").split(".")[-1],
                        "resource_id": res_id.split("/")[-1] if "/" in res_id else res_id,
                        "text": text,
                        "description": content_desc,
                        "clickable": is_clickable,
                        "editable": is_editable,
                        "center_coords": coords
                    })
            return json.dumps(nodes[:25], indent=2)  # Return top relevant elements
        except Exception as e:
            return json.dumps({"error": f"XML parse error: {str(e)}"})

    def _parse_bounds_center(self, bounds_str: str) -> Optional[List[int]]:
        try:
            pts = bounds_str.replace("][", ",").replace("[", "").replace("]", "").split(",")
            x1, y1, x2, y2 = map(int, pts)
            return [(x1 + x2) // 2, (y1 + y2) // 2]
        except Exception:
            return None

    def execute_interaction(self, action_type: str, target: str, value: Optional[str] = None) -> str:
        """
        Executes a concrete user action (tap, input_text, start_activity, press_back)
        and tracks it in the reproduction path.
        """
        timestamp = time.strftime("%H:%M:%S")
        action_log = {"step": len(self.execution_path) + 1, "time": timestamp, "type": action_type}

        if action_type == "tap":
            # Target is "x,y" coordinates
            coords = target.split(",")
            self._adb_exec(["shell", "input", "tap", coords[0].strip(), coords[1].strip()])
            action_log["command"] = f"adb shell input tap {coords[0].strip()} {coords[1].strip()}"
            action_log["description"] = f"Tap on coordinates ({target})"

        elif action_type == "input_text":
            # Value is the text to input
            safe_val = (value or "").replace(" ", "%s")
            self._adb_exec(["shell", "input", "text", safe_val])
            action_log["command"] = f"adb shell input text '{value}'"
            action_log["description"] = f"Enter text: '{value}'"

        elif action_type == "launch_activity":
            component = f"{self.package_name}/{target}" if "/" not in target else target
            self._adb_exec(["shell", "am", "start", "-n", component])
            action_log["command"] = f"adb shell am start -n {component}"
            action_log["description"] = f"Direct launch activity '{target}'"

        elif action_type == "press_back":
            self._adb_exec(["shell", "input", "keyevent", "4"])
            action_log["command"] = "adb shell input keyevent 4"
            action_log["description"] = "Press Back button"

        time.sleep(1.2)  # Wait for UI transition
        self.execution_path.append(action_log)
        return json.dumps({"status": "success", "recorded_step": action_log})

    def capture_evidence_artifact(self, check_id: str, label: str) -> Dict[str, Any]:
        """
        Captures a visual screenshot and logs recent logcat entries, associating
        them with the current execution breadcrumbs.
        """
        slug = f"{check_id.lower()}_{int(time.time())}"
        img_name = f"{slug}.png"
        log_name = f"{slug}.log"

        local_img = os.path.join(self.evidence_dir, img_name)
        local_log = os.path.join(self.evidence_dir, log_name)

        # 1. Capture Screenshot
        remote_png = f"/data/local/tmp/{img_name}"
        self._adb_exec(["shell", "screencap", "-p", remote_png])
        self._adb_exec(["pull", remote_png, local_img])
        self._adb_exec(["shell", "rm", "-f", remote_png])

        # 2. Slice Logcat
        log_dump = self._adb_exec(["logcat", "-d", "-t", "80"])
        with open(local_log, "w", encoding="utf-8", errors="replace") as f:
            f.write(log_dump)

        # 3. Compile reproduction command sequence
        repro_steps = [item["command"] for item in self.execution_path if "command" in item]

        return {
            "evidence_image": os.path.relpath(local_img, start="reporting"),
            "evidence_log": os.path.relpath(local_log, start="reporting"),
            "reproduction_sequence": repro_steps,
            "label": label
        }
from .constants import SEVERITY_ORDER


class Findings:
    def __init__(self):
        self.items = []

    def add(self, severity, surface, title, evidence=None, confidence=None):
        self.items.append({
            "severity": severity,
            "surface": surface,
            "title": title,
            "confidence": confidence or "medium",
            "evidence": evidence or {},
        })

    def sorted(self):
        return sorted(self.items,
                      key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    def as_list(self):
        return self.sorted()

    def __len__(self):
        return len(self.items)


def print_findings(findings):
    if not findings:
        return

    print("\n" + "=" * 46)
    print("  FINDINGS")
    print("=" * 46)

    for f in findings.sorted():
        conf = f.get("confidence", "medium")
        print(f"  [{f['severity'].upper():<8}] ({f['surface']}) {f['title']}  "
              f"<conf: {conf}>")

        for key, value in (f["evidence"] or {}).items():
            print(f"        {key}: {value}")

from pathlib import Path
from random import randint, choice
try:
    from faker import Faker
except ImportError:
    raise SystemExit("pip install faker")

fake = Faker()
root = Path(__file__).parent / "sandbox"
root.mkdir(parents=True, exist_ok=True)

def mk_person_file(i: int):
    name = fake.name()
    email = fake.email()
    phone = fake.phone_number()
    sin = f"{randint(100,999)}-{randint(100,999)}-{randint(100,999)}"
    cc = "".join(str(randint(0,9)) for _ in range(choice([16,15,14])))
    text = f"""
Customer Intake Form
Name: {name}
Email: {email}
Phone: {phone}
Canadian SIN: {sin}
Credit Card: {cc}
Notes: prefers contact after 6pm ET.
"""
    (root / f"intake_{i}.txt").write_text(text, encoding="utf-8")

for i in range(1, 7):
    mk_person_file(i)

(root / "README.md").write_text("# Demo Sandbox\nSynthetic files with fake PII.\n", encoding="utf-8")
print(f"Generated {len(list(root.glob('*.txt')))} files in {root}")

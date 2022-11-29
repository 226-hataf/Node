
url = ""

resources = []

for resource in resources:
    for action in ["create", "delete"]:
        create_role(f"zekoder-zestuio-{resource}-{action}")
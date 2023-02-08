import sys
import os

template_dashboard = """<!DOCTYPE html>
<html>
<body>

<h1>Gemini Self-Protector</h1>
<h5></h5>
</body>
</html>
    """

class _Template(object):

    def create_template():
        with open('gemini_protector/dashboard.html','w+', encoding="utf-8") as f:
            f.write(template_dashboard)

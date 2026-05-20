def get_safety_tips(risk_score):

    if risk_score < 40:
        return []

    return [
        "Do not enter passwords or banking information",
        "Avoid downloading files from this website",
        "Open the link in a sandbox or virtual machine if necessary",
        "Verify the domain name carefully before interacting",
        "Use updated antivirus protection",
        "Avoid logging into important accounts",
    ]

import sys
from app.predict import predict_url


TEST_CASES = [
    {
        'url': 'https://google.com',
        'min': 0,
        'max': 10,
        'desc': 'Known safe provider should be very low',
    },
    {
        'url': 'https://github.com',
        'min': 0,
        'max': 15,
        'desc': 'Popular developer platform should be low',
    },
    {
        'url': 'http://paypal-login-secure.xyz',
        'min': 80,
        'max': 95,
        'desc': 'Obvious phishing-style domain should be high',
    },
]


def run_tests():
    failures = []
    for tc in TEST_CASES:
        url = tc['url']
        min_r = tc['min']
        max_r = tc['max']
        label, score, reasons = predict_url(url)
        print(f"URL: {url}\n  Label: {label}\n  Score: {score}\n  Reasons: {reasons}\n")
        if not (min_r <= score <= max_r):
            failures.append((url, score, min_r, max_r))

    if failures:
        print("\nFAILED TESTS:\n")
        for f in failures:
            print(f"- {f[0]} scored {f[1]} (expected {f[2]}-{f[3]})")
        sys.exit(1)

    print("\nALL TESTS PASSED")


if __name__ == '__main__':
    run_tests()

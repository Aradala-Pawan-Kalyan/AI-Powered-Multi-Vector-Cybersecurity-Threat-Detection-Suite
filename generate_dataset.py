"""
generate_dataset.py (v2)
-------------------------
Builds a labeled training dataset covering a wider variety of phishing
patterns so the expanded feature set in features.py has real signal to
learn from: typosquatting, punycode, redirect parameters, malware-style
file extensions, homoglyphs, in addition to the original patterns.
"""

import random
import csv

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.com", "github.com",
    "microsoft.com", "apple.com", "linkedin.com", "netflix.com", "reddit.com",
    "nytimes.com", "bbc.com", "spotify.com", "dropbox.com", "adobe.com",
    "salesforce.com", "stackoverflow.com", "medium.com", "twitch.tv",
    "coursera.org", "khanacademy.org", "harvard.edu", "mit.edu", "who.int",
    "irs.gov", "usa.gov", "chase.com", "wellsfargo.com", "paypal.com",
    "shopify.com", "airbnb.com", "booking.com", "zoom.us", "slack.com",
    "notion.so", "figma.com", "canva.com", "wordpress.com", "cloudflare.com",
    "ebay.com", "fedex.com", "usps.com", "bankofamerica.com", "coinbase.com",
]

LEGIT_PATHS = [
    "", "/", "/home", "/about", "/products", "/blog/2025/09/article",
    "/user/settings", "/docs/api/v2", "/search?q=test", "/help/faq",
    "/account/profile", "/login", "/checkout/cart", "/news/today",
    "/contact-us", "/careers", "/support/tickets/123", "/pricing",
]

BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "chase", "wellsfargo", "irs", "instagram", "outlook",
    "linkedin", "bankofamerica", "coinbase", "dhl", "usps", "fedex",
    "ebay", "adobe", "dropbox", "whatsapp",
]

SUSPICIOUS_TLDS = ["xyz", "top", "club", "work", "click", "link", "gq",
                    "tk", "ml", "cf", "buzz", "loan", "men", "icu", "win",
                    "rest", "quest", "monster"]

KEYWORDS = ["secure", "login", "verify", "verification", "update", "account",
            "confirm", "signin", "billing", "suspend", "unlock", "alert",
            "recover", "wallet", "support", "security-check", "reset", "invoice"]

RANDOM_WORDS = ["portal", "center", "online", "service", "team", "help",
                "info", "web", "app", "id", "auth", "session", "user"]

MALWARE_EXTENSIONS = [".exe", ".scr", ".zip", ".apk", ".jar", ".msi"]
REDIRECT_PARAMS = ["redirect", "url", "next", "continue", "dest", "goto"]


def random_token(length=6):
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(letters) for _ in range(length))


def typo_variant(word: str) -> str:
    """Generates a typosquat-style variant of a brand/domain word:
    char swap, char drop, char duplicate, or adjacent-key substitution."""
    if len(word) < 4:
        return word + random.choice("aeiou")
    i = random.randint(1, len(word) - 2)
    op = random.choice(["swap", "drop", "dup", "sub"])
    if op == "swap":
        w = list(word)
        w[i], w[i + 1] = w[i + 1], w[i]
        return "".join(w)
    if op == "drop":
        return word[:i] + word[i + 1:]
    if op == "dup":
        return word[:i] + word[i] + word[i:]
    sub_map = {"a": "q", "o": "0", "l": "1", "e": "3", "i": "1", "s": "5"}
    ch = word[i]
    return word[:i] + sub_map.get(ch, ch) + word[i + 1:]


def make_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"
    if random.random() < 0.15:
        sub = random.choice(["www", "mail", "docs", "support", "shop", "api"])
        domain = f"{sub}.{domain}"
    if random.random() < 0.1:
        param = random.choice(["ref", "id", "page", "lang"])
        path = f"{path}?{param}={random_token(4)}"
    return f"{scheme}://{domain}{path}"


def make_phishing_url():
    style = random.choice([
        "brand_hyphen", "brand_subdomain", "ip_based", "shortener_style",
        "keyword_heavy", "random_domain", "typosquat", "punycode_style",
        "redirect_param", "malware_extension",
    ])
    brand = random.choice(BRANDS)
    tld = random.choice(SUSPICIOUS_TLDS)
    kw1 = random.choice(KEYWORDS)
    kw2 = random.choice(KEYWORDS)

    if style == "brand_hyphen":
        url = f"http://{kw1}-{brand}-{kw2}-{random_token(4)}.{tld}/{random.choice(['login','verify','signin'])}"
    elif style == "brand_subdomain":
        fake_sub = f"{brand}.{kw1}"
        url = f"http://{fake_sub}-{random_token(5)}.{random.choice(['com-secure.net','info','xyz'])}/account"
    elif style == "ip_based":
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        url = f"http://{ip}/{brand}/{kw1}.php"
    elif style == "shortener_style":
        shorteners = ["bit.ly", "tinyurl.com", "cutt.ly", "rebrand.ly"]
        url = f"http://{random.choice(shorteners)}/{random_token(7)}"
    elif style == "keyword_heavy":
        url = (f"http://{kw1}-{kw2}-{brand}-{random.choice(RANDOM_WORDS)}-"
               f"{random_token(3)}.{tld}/{kw1}/{kw2}.html")
    elif style == "typosquat":
        fake_domain = typo_variant(brand)
        tld_choice = random.choice(["com", "net", tld])
        url = f"http://{fake_domain}.{tld_choice}/{kw1}"
    elif style == "punycode_style":
        url = f"http://xn--{brand}-{random_token(4)}.{tld}/{kw1}"
    elif style == "redirect_param":
        legit_looking = random.choice(RANDOM_WORDS)
        param = random.choice(REDIRECT_PARAMS)
        target = f"http://{brand}-{kw1}.{tld}"
        url = f"http://{legit_looking}-{random_token(4)}.{tld}/click?{param}={target}"
    elif style == "malware_extension":
        ext = random.choice(MALWARE_EXTENSIONS)
        url = f"http://{kw1}-{brand}-{random_token(4)}.{tld}/download/invoice{ext}"
    else:  # random_domain
        url = f"http://{random_token(10)}-{random_token(4)}.{tld}/{kw1}"

    return url


def build_dataset(n_legit=2000, n_phish=2000, out_path="dataset.csv"):
    rows = []
    for _ in range(n_legit):
        rows.append((make_legit_url(), 0))
    for _ in range(n_phish):
        rows.append((make_phishing_url(), 1))

    random.shuffle(rows)

    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {out_path} "
          f"({n_legit} safe / {n_phish} phishing)")


if __name__ == "__main__":
    build_dataset()

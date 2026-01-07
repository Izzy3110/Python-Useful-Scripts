#!/usr/bin/env python3
import sys
import dns.resolver

# Settings
GLOBAL_OPTIONS_DEBUG_SHOW_RECORD_VALUE_IN_RESULTS_OUTPUT = True


class DNSChecker:
    STRICT_SELECTOR = False

    def __init__(self, domain_name: str, dkim_selector: str | None = None):
        self.domain_name = domain_name

        if dkim_selector:
            # Explicit selector overrides everything
            self.DKIM_SELECTORS = [dkim_selector]
            self.STRICT_SELECTOR = True
        else:
            self.DKIM_SELECTORS = self.selectors_from_file()

    # ---------- DKIM ----------
    def selectors_from_file(self) -> list[str]:
        selectors_clean: list[str] = []

        try:
            with open(f"./dkim/{self.domain_name}.selectors.lst", encoding="utf-8") as selectors_file:
                selectors = selectors_file.read().splitlines()

            with open("./dkim/selectors.lst", encoding="utf-8") as default_file:
                selectors += default_file.read().splitlines()

        except FileNotFoundError:
            with open("./dkim/selectors.lst", encoding="utf-8") as selectors_file:
                selectors = selectors_file.read().splitlines()

        for sel in selectors:
            if sel and sel not in selectors_clean:
                selectors_clean.append(sel)

        return selectors_clean

    def _check_dkim_selector(self, dkim_selector: str):
        dkim_domain = f"{dkim_selector}._domainkey.{self.domain_name}"

        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            for rdata in answers:
                record_value = "".join(part.decode() for part in rdata.strings)
                if "v=DKIM1" in record_value:
                    return True, record_value
            return False, None

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False, None
        except Exception as exc:
            return False, str(exc)

    def check_dkim(self):
        dkim_results = {}

        for dkim_selector in self.DKIM_SELECTORS:
            valid, dns_record = self._check_dkim_selector(dkim_selector)
            if valid:
                dkim_results[dkim_selector] = dns_record

        return dkim_results


def usage():
    print("Usage:")
    print("  ./test_dns-dkim.py dkim <domain> [selector]")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        usage()

    dns_mode = sys.argv[1]
    domain = sys.argv[2]
    selector = sys.argv[3] if len(sys.argv) == 4 else None

    checker = DNSChecker(domain, selector)

    if dns_mode == "dkim":
        results = checker.check_dkim()

        if results:
            success_selector = next(iter(results))
            print(f'✅ DKIM found for {domain} with DKIM selector "{success_selector}"')

            if GLOBAL_OPTIONS_DEBUG_SHOW_RECORD_VALUE_IN_RESULTS_OUTPUT:
                x = 5
                y = 50
                z = (x + y) + 6

                print("\n")
                print(("=" * x) + " DEBUG " + ("=" * y))
                for _, record in results.items():
                    print("\nValue:")
                    print(record)
                print("\n")
                print(("=" * z))
        else:
            print(f"❌ No DKIM record found for {domain}")
            if checker.STRICT_SELECTOR:
                print(f"\nTested Selectors: {", ".join(checker.DKIM_SELECTORS)}")
    else:
        usage()

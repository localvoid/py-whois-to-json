"""
Usage example:

$ python whois.py abc.com

"""
import json
import re
import subprocess
import sys


class WhoisError(RuntimeError):
    pass


_REGEX = {
    'com': {
        'domain_name': r'Domain Name:\s?(.+)',
        'registrar': r'Registrar:\s?(.+)',
        'whois_server': r'Whois Server:\s?(.+)',
        'referral_url': r'Referral URL:\s?(.+)',
        'updated_date': r'Updated Date:\s?(.+)',
        'creation_date': r'Creation Date:\s?(.+)',
        'expiration_date': r'Expiration Date:\s?(.+)',
        'name_servers': r'Name Server:\s?(.+)',
        'status': r'Status:\s?(.+)',
        'emails': r'[\w.-]+@[\w.-]+\.[\w]{2,4}',
    },
    'ru': {
        'domain_name': r'domain:\s*(.+)',
        'registrar': r'registrar:\s*(.+)',
        'creation_date': r'created:\s*(.+)',
        'expiration_date': r'paid-till:\s*(.+)',
        'name_servers': r'nserver:\s*(.+)',
        'status': r'state:\s*(.+)',
        'emails': r'[\w.-]+@[\w.-]+\.[\w]{2,4}',
    },
    'name': {
        'domain_name_id': r'Domain Name ID:\s*(.+)',
        'domain_name': r'Domain Name:\s*(.+)',
        'registrar_id': r'Sponsoring Registrar ID:\s*(.+)',
        'registrar': r'Sponsoring Registrar:\s*(.+)',
        'registrant_id': r'Registrant ID:\s*(.+)',
        'admin_id': r'Admin ID:\s*(.+)',
        'technical_id': r'Tech ID:\s*(.+)',
        'billing_id': r'Billing ID:\s*(.+)',
        'creation_date': r'Created On:\s*(.+)',
        'expiration_date': r'Expires On:\s*(.+)',
        'updated_date': r'Updated On:\s*(.+)',
        'name_server_ids': r'Name Server ID:\s*(.+)',
        'name_servers': r'Name Server:\s*(.+)',
        'status': r'Domain Status:\s*(.+)',
    },
    'us': {
        'domain_name': r'Domain Name:\s*(.+)',
        'domain_id': r'Domain ID:\s*(.+)',
        'registrar': r'Sponsoring Registrar:\s*(.+)',
        'registrar_id': r'Sponsoring Registrar IANA ID:\s*(.+)',
        'registrar_url': r'Registrar URL \(registration services\):\s*(.+)',
        'status': r'Domain Status:\s*(.+)',
        'registrant_id': r'Registrant ID:\s*(.+)',
        'registrant_name': r'Registrant Name:\s*(.+)',
        'registrant_address1': r'Registrant Address1:\s*(.+)',
        'registrant_address2': r'Registrant Address2:\s*(.+)',
        'registrant_city': r'Registrant City:\s*(.+)',
        'registrant_state_province': r'Registrant State/Province:\s*(.+)',
        'registrant_postal_code': r'Registrant Postal Code:\s*(.+)',
        'registrant_country': r'Registrant Country:\s*(.+)',
        'registrant_country_code': r'Registrant Country Code:\s*(.+)',
        'registrant_phone_number': r'Registrant Phone Number:\s*(.+)',
        'registrant_email': r'Registrant Email:\s*(.+)',
        'registrant_application_purpose': r'Registrant Application Purpose:\s*(.+)',
        'registrant_nexus_category': r'Registrant Nexus Category:\s*(.+)',
        'admin_id': r'Administrative Contact ID:\s*(.+)',
        'admin_name': r'Administrative Contact Name:\s*(.+)',
        'admin_address1': r'Administrative Contact Address1:\s*(.+)',
        'admin_address2': r'Administrative Contact Address2:\s*(.+)',
        'admin_city': r'Administrative Contact City:\s*(.+)',
        'admin_state_province': r'Administrative Contact State/Province:\s*(.+)',
        'admin_postal_code': r'Administrative Contact Postal Code:\s*(.+)',
        'admin_country': r'Administrative Contact Country:\s*(.+)',
        'admin_country_code': r'Administrative Contact Country Code:\s*(.+)',
        'admin_phone_number': r'Administrative Contact Phone Number:\s*(.+)',
        'admin_email': r'Administrative Contact Email:\s*(.+)',
        'admin_application_purpose': r'Administrative Application Purpose:\s*(.+)',
        'admin_nexus_category': r'Administrative Nexus Category:\s*(.+)',
        'billing_id': r'Billing Contact ID:\s*(.+)',
        'billing_name': r'Billing Contact Name:\s*(.+)',
        'billing_address1': r'Billing Contact Address1:\s*(.+)',
        'billing_address2': r'Billing Contact Address2:\s*(.+)',
        'billing_city': r'Billing Contact City:\s*(.+)',
        'billing_state_province': r'Billing Contact State/Province:\s*(.+)',
        'billing_postal_code': r'Billing Contact Postal Code:\s*(.+)',
        'billing_country': r'Billing Contact Country:\s*(.+)',
        'billing_country_code': r'Billing Contact Country Code:\s*(.+)',
        'billing_phone_number': r'Billing Contact Phone Number:\s*(.+)',
        'billing_email': r'Billing Contact Email:\s*(.+)',
        'billing_application_purpose': r'Billing Application Purpose:\s*(.+)',
        'billing_nexus_category': r'Billing Nexus Category:\s*(.+)',
        'tech_id': r'Technical Contact ID:\s*(.+)',
        'tech_name': r'Technical Contact Name:\s*(.+)',
        'tech_address1': r'Technical Contact Address1:\s*(.+)',
        'tech_address2': r'Technical Contact Address2:\s*(.+)',
        'tech_city': r'Technical Contact City:\s*(.+)',
        'tech_state_province': r'Technical Contact State/Province:\s*(.+)',
        'tech_postal_code': r'Technical Contact Postal Code:\s*(.+)',
        'tech_country': r'Technical Contact Country:\s*(.+)',
        'tech_country_code': r'Technical Contact Country Code:\s*(.+)',
        'tech_phone_number': r'Technical Contact Phone Number:\s*(.+)',
        'tech_email': r'Technical Contact Email:\s*(.+)',
        'tech_application_purpose': r'Technical Application Purpose:\s*(.+)',
        'tech_nexus_category': r'Technical Nexus Category:\s*(.+)',
        'name_servers': r'Name Server:\s*(.+)',  # list of name servers
        'created_by_registrar': r'Created by Registrar:\s*(.+)',
        'last_updated_by_registrar': r'Last Updated by Registrar:\s*(.+)',
        'creation_date': r'Domain Registration Date:\s*(.+)',
        'expiration_date': r'Domain Expiration Date:\s*(.+)',
        'updated_date': r'Domain Last Updated Date:\s*(.+)',
    },
    'me': {
        'domain_id': r'Domain ID:(.+)',
        'domain_name': r'Domain Name:(.+)',
        'creation_date': r'Domain Create Date:(.+)',
        'updated_date': r'Domain Last Updated Date:(.+)',
        'expiration_date': r'Domain Expiration Date:(.+)',
        'transfer_date': r'Last Transferred Date:(.+)',
        'trademark_name': r'Trademark Name:(.+)',
        'trademark_country': r'Trademark Country:(.+)',
        'trademark_number': r'Trademark Number:(.+)',
        'trademark_application_date': r'Date Trademark Applied For:(.+)',
        'trademark_registration_date': r'Date Trademark Registered:(.+)',
        'registrar': r'Sponsoring Registrar:(.+)',
        'created_by': r'Created by:(.+)',
        'updated_by': r'Last Updated by Registrar:(.+)',
        'status': r'Domain Status:(.+)',
        'registrant_id': r'Registrant ID:(.+)',
        'registrant_name': r'Registrant Name:(.+)',
        'registrant_org': r'Registrant Organization:(.+)',
        'registrant_address': r'Registrant Address:(.+)',
        'registrant_address2': r'Registrant Address2:(.+)',
        'registrant_address3': r'Registrant Address3:(.+)',
        'registrant_city': r'Registrant City:(.+)',
        'registrant_state_province': r'Registrant State/Province:(.+)',
        'registrant_country': r'Registrant Country/Economy:(.+)',
        'registrant_postal_code': r'Registrant Postal Code:(.+)',
        'registrant_phone': r'Registrant Phone:(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext\.:(.+)',
        'registrant_fax': r'Registrant FAX:(.+)',
        'registrant_fax_ext': r'Registrant FAX Ext\.:(.+)',
        'registrant_email': r'Registrant E-mail:(.+)',
        'admin_id': r'Admin ID:(.+)',
        'admin_name': r'Admin Name:(.+)',
        'admin_org': r'Admin Organization:(.+)',
        'admin_address': r'Admin Address:(.+)',
        'admin_address2': r'Admin Address2:(.+)',
        'admin_address3': r'Admin Address3:(.+)',
        'admin_city': r'Admin City:(.+)',
        'admin_state_province': r'Admin State/Province:(.+)',
        'admin_country': r'Admin Country/Economy:(.+)',
        'admin_postal_code': r'Admin Postal Code:(.+)',
        'admin_phone': r'Admin Phone:(.+)',
        'admin_phone_ext': r'Admin Phone Ext\.:(.+)',
        'admin_fax': r'Admin FAX:(.+)',
        'admin_fax_ext': r'Admin FAX Ext\.:(.+)',
        'admin_email': r'Admin E-mail:(.+)',
        'tech_id': r'Tech ID:(.+)',
        'tech_name': r'Tech Name:(.+)',
        'tech_org': r'Tech Organization:(.+)',
        'tech_address': r'Tech Address:(.+)',
        'tech_address2': r'Tech Address2:(.+)',
        'tech_address3': r'Tech Address3:(.+)',
        'tech_city': r'Tech City:(.+)',
        'tech_state_province': r'Tech State/Province:(.+)',
        'tech_country': r'Tech Country/Economy:(.+)',
        'tech_postal_code': r'Tech Postal Code:(.+)',
        'tech_phone': r'Tech Phone:(.+)',
        'tech_phone_ext': r'Tech Phone Ext\.:(.+)',
        'tech_fax': r'Tech FAX:(.+)',
        'tech_fax_ext': r'Tech FAX Ext\.:(.+)',
        'tech_email': r'Tech E-mail:(.+)',
        'name_servers': r'Nameservers:(.+)',
    },
    'uk': {
        'domain_name': r'Domain name:\n\s*(.+)',
        'registrar': r'Registrar:\n\s*(.+)',
        'registrar_url': r'URL:\s*(.+)',
        'status': r'Registration status:\n\s*(.+)',
        'registrant_name': r'Registrant:\n\s*(.+)',
        'creation_date': r'Registered on:\s*(.+)',
        'expiration_date': r'Renewal date:\s*(.+)',
        'updated_date': r'Last updated:\s*(.+)',
    }
}

for _, rules in _REGEX.items():
    for name, rule in rules.items():
        rules[name] = re.compile(rule)

_REGEX['net'] = _REGEX['com']
_REGEX['org'] = _REGEX['com']


def parse_data(data, rules):
    result = {}
    for name, rule in rules.items():
        result[name] = rule.findall(data)
    return result

def whois(url):
    try:
        out = subprocess.check_output(['whois', url])
    except subprocess.CalledProcessError:
        raise WhoisError()
    _, tld = url.rsplit('.')
    result = parse_data(out, _REGEX[tld])
    return json.dumps(result)


if __name__ == "__main__":
    print(whois(sys.argv[1]))

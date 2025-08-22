from app import create_app
from app.models import CertificateAuthority

app = create_app()

with app.app_context():
    ca = CertificateAuthority.query.get(4)
    print(f'CA exists: {ca is not None}')
    if ca:
        print(f'ACME enabled: {ca.acme_enabled}')
    else:
        print('CA not found')
        # 列出所有CA
        all_cas = CertificateAuthority.query.all()
        print(f'Total CAs: {len(all_cas)}')
        for c in all_cas:
            print(f'  CA ID: {c.id}, Name: {c.name}, ACME enabled: {c.acme_enabled}')
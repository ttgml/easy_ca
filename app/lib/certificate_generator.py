from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import uuid

class CertificateGenerator:
    @staticmethod
    def generate_key_pair(key_type='RSA', key_size=2048, ec_curve='P-256'):
        """生成密钥对"""
        if key_type == 'RSA':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
            )
        else:  # ECDSA
            curve_map = {
                'P-256': ec.SECP256R1(),
                'P-384': ec.SECP384R1(),
                'P-521': ec.SECP521R1(),
            }
            private_key = ec.generate_private_key(curve_map[ec_curve])
        return private_key

    @staticmethod
    def create_ca_certificate(private_key, name, common_name, organization=None, organizational_unit=None,
                              country=None, state=None, locality=None, validity_years=10,
                              hash_algorithm='SHA-256', path_length=None, key_usage=None,
                              crl_distribution_points=None, authority_info_access=None):
        """创建CA证书"""
        # 创建证书主体
        subject_attrs = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]

        # 添加组织信息（如果有）
        if organization:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

        # 添加组织单位信息（如果有）
        if organizational_unit:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))

        # 添加国家信息（如果有）
        if country:
            subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

        # 添加省/州信息（如果有）
        if state:
            subject_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))

        # 添加城市信息（如果有）
        if locality:
            subject_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

        subject = x509.Name(subject_attrs)
        issuer = subject  # 自签名证书

        # 设置证书有效期
        valid_from = datetime.now(timezone.utc)
        valid_to = valid_from + timedelta(days=365 * validity_years)

        # 创建证书生成器
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
        )

        # 添加基本约束扩展
        path_length_value = int(path_length) if path_length else None
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length_value), critical=True,
        )

        # 添加密钥用法扩展（如果有）
        if key_usage:
            key_usage_extension = x509.KeyUsage(
                digital_signature='digital_signature' in key_usage,
                content_commitment=False,  # non_repudiation
                key_encipherment='key_encipherment' in key_usage,
                data_encipherment='data_encipherment' in key_usage,
                key_agreement='key_agreement' in key_usage,
                key_cert_sign='key_cert_sign' in key_usage,
                crl_sign='crl_sign' in key_usage,
                encipher_only=False,
                decipher_only=False
            )
            cert_builder = cert_builder.add_extension(key_usage_extension, critical=False)

        # 添加CRL分发点扩展（如果有）
        if crl_distribution_points:
            from cryptography.x509 import DistributionPoint
            crl_dp = DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_distribution_points)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
            cert_builder = cert_builder.add_extension(
                x509.CRLDistributionPoints([crl_dp]), critical=False
            )

        # 添加权威信息访问扩展（如果有）
        if authority_info_access:
            from cryptography.x509 import AuthorityInformationAccess, AccessDescription
            from cryptography.x509.oid import AuthorityInformationAccessOID
            aia = AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(authority_info_access)
            )
            cert_builder = cert_builder.add_extension(
                x509.AuthorityInformationAccess([aia]), critical=False
            )

        # 签名证书
        hash_algorithm_map = {
            'SHA-256': hashes.SHA256(),
            'SHA-384': hashes.SHA384(),
            'SHA-512': hashes.SHA512(),
        }
        algorithm = hash_algorithm_map.get(hash_algorithm, hashes.SHA256())

        certificate = cert_builder.sign(
            private_key=private_key,
            algorithm=algorithm,
        )

        return certificate, valid_from, valid_to

    @staticmethod
    def create_end_entity_certificate(cert_private_key, ca_private_key, ca_cert, common_name, sans=None,
                                     validity_days=365, hash_algorithm='SHA-256', key_usage=None,
                                     extended_key_usage=None, is_ca=False, path_length=None,
                                     crl_distribution_points=None, authority_info_access=None):
        """创建终端实体证书"""
        # 创建证书主体
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # 颁发者是CA
        issuer = ca_cert.subject

        # 设置证书有效期
        valid_from = datetime.now(timezone.utc)
        valid_to = valid_from + timedelta(days=validity_days)

        # 创建证书生成器
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(cert_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
        )

        # 添加基本约束扩展
        if is_ca:
            path_length_value = int(path_length) if path_length else None
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length_value), critical=True,
            )
        else:
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )

        # 添加密钥用法扩展
        if key_usage:
            key_usage_value = x509.KeyUsage(
                digital_signature='digitalSignature' in key_usage,
                content_commitment=False,
                key_encipherment='keyEncipherment' in key_usage,
                data_encipherment='dataEncipherment' in key_usage,
                key_agreement='keyAgreement' in key_usage,
                key_cert_sign='keyCertSign' in key_usage,
                crl_sign='cRLSign' in key_usage,
                encipher_only=False,
                decipher_only=False
            )
            cert_builder = cert_builder.add_extension(key_usage_value, critical=True)

        # 添加扩展密钥用法扩展
        if extended_key_usage:
            extended_key_usage_oids = []
            if 'serverAuth' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)
            if 'clientAuth' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)
            if 'codeSigning' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)
            if 'emailProtection' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)
            if 'timeStamping' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.TIME_STAMPING)

            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage(extended_key_usage_oids),
                critical=False
            )

        # 添加SANs扩展（如果有）
        if sans:
            san_list = [x509.DNSName(san) for san in sans]
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        # 签名证书
        hash_algorithm_map = {
            'SHA-256': hashes.SHA256(),
            'SHA-384': hashes.SHA384(),
            'SHA-512': hashes.SHA512(),
        }

        certificate = cert_builder.sign(
            private_key=ca_private_key,
            algorithm=hash_algorithm_map[hash_algorithm],
        )

        return certificate, valid_from, valid_to

    @staticmethod
    def convert_to_pem(private_key, certificate):
        """将私钥和证书转换为PEM格式"""
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        certificate_pem = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')

        return private_key_pem, certificate_pem

    @staticmethod
    def create_certificate_from_csr(csr_public_key, ca_private_key, ca_cert, common_name, sans=None,
                                   validity_days=365, hash_algorithm='SHA-256', key_usage=None,
                                   extended_key_usage=None, is_ca=False, path_length=None,
                                   crl_distribution_points=None, authority_info_access=None):
        """从CSR公钥创建证书（用于ACME场景）"""
        # 创建证书主体
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # 颁发者是CA
        issuer = ca_cert.subject

        # 设置证书有效期
        valid_from = datetime.now(timezone.utc)
        valid_to = valid_from + timedelta(days=validity_days)

        # 创建证书生成器
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(csr_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
        )

        # 添加基本约束扩展
        if is_ca:
            path_length_value = int(path_length) if path_length else None
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length_value), critical=True,
            )
        else:
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )

        # 添加密钥用法扩展
        if key_usage:
            key_usage_value = x509.KeyUsage(
                digital_signature='digitalSignature' in key_usage,
                content_commitment=False,
                key_encipherment='keyEncipherment' in key_usage,
                data_encipherment='dataEncipherment' in key_usage,
               key_agreement='keyAgreement' in key_usage,
                key_cert_sign='keyCertSign' in key_usage,
                crl_sign='cRLSign' in key_usage,
                encipher_only=False,
                decipher_only=False
            )
            cert_builder = cert_builder.add_extension(key_usage_value, critical=True)

        # 添加扩展密钥用法扩展
        if extended_key_usage:
            extended_key_usage_oids = []
            if 'serverAuth' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)
            if 'clientAuth' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)
            if 'codeSigning' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)
            if 'emailProtection' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)
            if 'timeStamping' in extended_key_usage:
                extended_key_usage_oids.append(x509.ExtendedKeyUsageOID.TIME_STAMPING)

            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage(extended_key_usage_oids),
                critical=False
            )

        # 添加SANs扩展（如果有）
        if sans:
            san_list = [x509.DNSName(san) for san in sans]
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        # 签名证书
        hash_algorithm_map = {
            'SHA-256': hashes.SHA256(),
            'SHA-384': hashes.SHA384(),
            'SHA-512': hashes.SHA512(),
        }

        certificate = cert_builder.sign(
            private_key=ca_private_key,
            algorithm=hash_algorithm_map[hash_algorithm],
        )

        return certificate, valid_from, valid_to
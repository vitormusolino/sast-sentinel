"""Criptografia e integracoes vulneraveis."""

import xml.etree.ElementTree as ET

import requests
from Crypto.Cipher import DES


def encrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)  # EXPECT: CWE-327
    return cipher.encrypt(data)


def parse_invoice(xml_text):
    return ET.fromstring(xml_text)  # EXPECT: CWE-611


def call_partner_api(payload):
    return requests.post("https://partner.example.com/api", json=payload, verify=False, timeout=5)  # EXPECT: CWE-295

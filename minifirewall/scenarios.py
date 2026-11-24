"""Hazir senaryolar.

Her senaryo; bir varsayilan politika, stateful bayragi, opsiyonel flood
siniri ve sirali kural listesinden olusur. Sunumda tek tikla farkli ag
tasarimlari arasinda gecis yapmak icin kullanilir.
"""

from __future__ import annotations

from .engine import FLOOD_DEFAULT, Firewall
from .rules import Rule

SCENARIOS: dict[str, dict] = {
    "allowall": {
        "label": "1 - Açık firewall (varsayılan ALLOW)",
        "description": (
            "Hiç kural yok ve varsayılan politika ALLOW. Tüm trafik geçer. "
            "Saldırıların ne kadar etkili olduğunu göstermek için."
        ),
        "default_policy": "allow",
        "stateful": False,
        "rules": [],
    },
    "web": {
        "label": "2 - Web sunucusu (temel ACL)",
        "description": (
            "Varsayılan DENY. Sadece web, DNS ve uygulama→veritabanı "
            "trafiği açık. SSH dışarıdan kapalı."
        ),
        "default_policy": "deny",
        "stateful": False,
        "rules": [
            "allow tcp any any 10.0.0.10 80   # HTTP - herkese açık",
            "allow tcp any any 10.0.0.10 443  # HTTPS - herkese açık",
            "allow udp any any 10.0.0.53 53   # DNS sorguları",
            "allow tcp 10.0.0.0/24 any 10.0.0.30 3306  # Uygulama → DB",
            "deny  tcp any any 10.0.0.20 22   # SSH: dışarıdan erişim yok",
        ],
    },
    "bastion": {
        "label": "3 - SSH bastion (kaynak IP kısıtlı)",
        "description": (
            "SSH sadece ofis subnetine (203.0.113.0/24) açık. Aynı port, "
            "farklı kaynak IP için farklı sonuç: IP tabanlı filtreleme."
        ),
        "default_policy": "deny",
        "stateful": False,
        "rules": [
            "allow tcp 203.0.113.0/24 any 10.0.0.20 22  # SSH: sadece ofis",
            "allow tcp any any 10.0.0.10 443  # HTTPS herkese açık",
            "allow udp any any 10.0.0.53 53   # DNS",
        ],
    },
    "dmz": {
        "label": "4 - Katmanlı / DMZ (ağ ayırma)",
        "description": (
            "Web sunucusu DMZ'de. DMZ'den iç veritabanına erişim yasak; "
            "sadece uygulama sunucusu (10.0.0.25) DB'ye konuşabilir."
        ),
        "default_policy": "deny",
        "stateful": False,
        "rules": [
            "deny  tcp 10.0.0.10 any 10.0.0.30 3306  # DMZ → DB YASAK",
            "allow tcp 10.0.0.25 any 10.0.0.30 3306  # App → DB serbest",
            "allow tcp any any 10.0.0.10 443  # HTTPS",
            "allow udp any any 10.0.0.53 53   # DNS",
        ],
    },
    "lockdown": {
        "label": "5 - Saldırı altında (kademeli savunma)",
        "description": (
            "Saldırgan IP'si (198.51.100.66) tüm portlardan tamamen "
            "engellenir. Kalan trafik için sadece HTTPS açık."
        ),
        "default_policy": "deny",
        "stateful": False,
        "rules": [
            "deny  tcp 198.51.100.66/32 any any any  # Saldırganı kes",
            "allow tcp 10.0.0.0/24 any 10.0.0.10 443  # İç ağa HTTPS",
            "allow udp 10.0.0.0/24 any 10.0.0.53 53   # İç ağa DNS",
        ],
    },
    "stateful": {
        "label": "6 - Stateful inspection",
        "description": (
            "Sadece iç ağdan dışarı HTTPS çıkışı açık. Dönüş paketleri "
            "kural listesinde olmasa da oturum tablosu sayesinde geçer."
        ),
        "default_policy": "deny",
        "stateful": True,
        "rules": [
            "allow tcp 10.0.0.0/24 any any 443  # İç ağdan dışarı HTTPS",
        ],
    },
    "flood": {
        "label": "7 - Flood guard (hız sınırı)",
        "description": (
            f"HTTPS herkese açık ama bir kaynak saniyede {FLOOD_DEFAULT} "
            "paketten fazla gönderemez. Tek kaynaklı SYN seli kesilir; "
            "çok kaynaklı DDoS ise kaynak başına limiti atlatır!"
        ),
        "default_policy": "deny",
        "stateful": False,
        "flood_limit": FLOOD_DEFAULT,
        "rules": [
            "allow tcp any any 10.0.0.10 443  # HTTPS herkese açık",
            "allow tcp any any 10.0.0.10 80   # HTTP herkese açık",
            "allow udp any any 10.0.0.53 53   # DNS",
        ],
    },
    "messy": {
        "label": "8 - Hatalı kural sırası (tuzak!)",
        "description": (
            "Yanlışlıkla en üste konan geniş bir ALLOW kuralı, altındaki "
            "SSH yasağını etkisiz bırakıyor. İlk eşleşen kazanır!"
        ),
        "default_policy": "deny",
        "stateful": False,
        "rules": [
            "allow tcp any any any any        # 'Geçici' her şeye izin (UNUTULDU)",
            "deny  tcp any any 10.0.0.20 22   # SSH yasağı (asla çalışmaz!)",
            "allow tcp any any 10.0.0.10 443  # HTTPS",
            "allow tcp any any 10.0.0.10 443  # HTTPS (kopya)",
        ],
    },
}

DEFAULT_SCENARIO = "web"


def scenario_catalog() -> list[dict]:
    """Arayuzdeki senaryo menusu icin ozet liste."""
    return [
        {
            "name": name,
            "label": data["label"],
            "description": data["description"],
            "default_policy": data["default_policy"],
            "stateful": data["stateful"],
            "flood_limit": data.get("flood_limit"),
            "rule_count": len(data["rules"]),
        }
        for name, data in SCENARIOS.items()
    ]


def build(name: str) -> Firewall:
    """Senaryo adindan hazir bir Firewall nesnesi uretir."""
    if name not in SCENARIOS:
        raise ValueError(f"Bilinmeyen senaryo: {name!r}")
    data = SCENARIOS[name]
    rules = [Rule.from_text(line) for line in data["rules"]]
    return Firewall(
        rules=rules,
        default_policy=data["default_policy"],
        stateful=data["stateful"],
        flood_limit=data.get("flood_limit"),
    )

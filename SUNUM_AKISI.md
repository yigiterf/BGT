# 🎤 Sunum Akışı — MiniFirewall Lab

**Konu:** Chapter 10 — *Mini Firewall Lab: IP, Port ve Protokol Tabanlı Paket Filtreleme Simülasyonu*
**Süre:** 15–20 dakika (≈3–4 dk teori, geri kalanı canlı gösterim)
**Format:** Tek bir tarayıcı sekmesi (web arayüzü) + bir terminal sekmesi, aralarında geçiş yaparak

> Bu dosya; ne söyleyeceğini, ne zaman tıklayacağını ve hangi komutu çalıştıracağını dakika dakika anlatır. Terimlerden emin değilsen önce **[KAVRAMLAR.md](KAVRAMLAR.md)**'yi oku — orada firewall, IP, port, protokol gibi her şey sıfırdan anlatılıyor. Burada artık o kavramları bildiğini varsayıyorum; odak noktası **her senaryonun gerçek hayatta neyi temsil ettiği.**

---

## 0. Hazırlık (sunumdan önce, 2 dakika)

- [ ] Terminalde proje klasöründesin: `cd "Sunum Ödevi"`
- [ ] İkinci bir terminal sekmesi/penceresi aç (demo + web arasında geçiş için)
- [ ] Web arayüzünü başlat ve tarayıcıda sekme olarak açık bırak:
  ```bash
  python3 run.py --scenario web
  ```
  (Tarayıcı otomatik açılır → `http://localhost:8080`)
- [ ] Tarayıcı penceresini büyüt, yazı tipi/ekran paylaşımı zoom'u test et (özellikle **Kural izi** ve **kod çekmecesi** küçük yazı içeriyor)
- [ ] Yedek olarak: `python3 -m unittest discover -s tests` çalıştır, 43 testin yeşil olduğunu gör (sunumda "test ettim" diyebilmek için)
- [ ] Varsa projektör/ekran koyu tema ile daha okunaklı — arayüz zaten koyu tema

---

## 1. Açılış kancası (0:00 – 1:00) — 1 dakika

**Amaç:** İlk 10 saniyede dikkat çek, "yine bir slayt sunumu" hissi vermesin.

Ekranda **hiçbir şey açmadan** başla, sonra web arayüzünü göster:

> "Her gün internete çıkan her paket, biri tarafından 'geçsin mi, geçmesin mi' diye kontrol ediliyor. Bugün o kontrolü yapan şeyi — bir firewall'u — sıfırdan yazdım ve içini açtım. Slayt yok, direkt koda ve çalışan sisteme bakacağız."

Web arayüzünü göster (zaten açık), 3 saniye sessiz kalıp topolojinin oturmasını bekle.

---

## 2. Teorik çerçeve (1:00 – 4:30) — ~3.5 dakika

**Amaç:** Kitaptaki (Ch. 10) kavramları isim vererek geçmek. Slayt yok; konuşurken web arayüzündeki **kural listesi** ve **topoloji**yi işaret et. Her kavramın uzun açıklaması [KAVRAMLAR.md](KAVRAMLAR.md)'de — burada sadece sunumda söyleyeceğin kısa versiyonu var.

1. **Packet filtering nedir?** — "Bir paket; kaynak IP, hedef IP, protokol (TCP/UDP/ICMP) ve port'tan oluşan bir **5-tuple**'dır. Firewall bu 5 alana bakarak karar verir, paketin *içeriğini* okumaz." → Kural listesindeki bir satırı göster: `allow tcp any any 10.0.0.10 443`.
2. **ACL ve Allow/Deny** — "Kurallar yukarıdan aşağı sırayla denenir, **ilk eşleşen kazanır**." (Kural listesini işaret et.)
3. **Implicit deny** — "Hiçbir kural eşleşmezse ne olur? Biz varsayılan politikayı DENY seçtik: açıkça izin verilmeyen her şey engellenir. Güvenlik dünyasının altın kuralı: **önce her şeyi kapat, sonra ihtiyacın olanı aç.**" (Üstteki ALLOW/DENY anahtarını göster.)
4. **Stateful inspection** — "Gerçek firewall'lar her paketi sıfırdan değerlendirmez; bir bağlantı bir kere izin aldıysa, dönüş paketlerini hatırlar. Az sonra bunu stateful anahtarını açıp/kapatarak canlı göstereceğim."
5. **Network separation / DMZ** — "Dış dünya, DMZ (web sunucusu) ve iç ağ (veritabanı) birbirinden ayrı tutulur. DMZ ele geçirilse bile iç veritabanına sıçrayamaz." (Topolojideki Web/DB düğümlerini göster.)

> Kapanış cümlesi: "Şimdi bu 5 kavramı tek tek canlı tetikleyeceğim — her biri gerçek kod çalıştırıyor, slayt değil. Ama önce sahnede kimin kim olduğunu bir kere netleştireyim, yoksa IP adresleri havada kalır."

---

## 3. Sahne haritası: bu senaryolarda "kim kim"? (4:30 – 5:15) — ~45 saniye

**Bu bölüm, az önceki kullanıcı sorusunun tam cevabı: senaryolar "havada" değil — hepsi aynı hayali şirketin ağını farklı güvenlik seviyelerinde gösteriyor.** Bunu sunumda tek cümleyle, ama mutlaka söyle — yoksa izleyici "Web sunucusu senaryosu da ne demek?" diye kafası karışık kalır.

> "Tüm senaryolarda sabit bir kurgu var: hayali bir şirketimiz var. Şirketin bir web sitesi, bir DNS'i, bir SSH ile yönetilen sunucusu ve bir veritabanı var. Bunların dışında bir de *saldırgan* ve şirketin *güvenilir ofis ağı* var. Her senaryo, bu şirketin **firewall kurallarını farklı şekilde yapılandırdığımızda** ne olduğunu gösteriyor — yani aynı tiyatro, farklı perdeler."

Ekranda (topoloji panelinde) işaret ederek say:

| Kim? | IP (projede) | Rolü |
|---|---|---|
| 🌐 **Web sunucusu** | `10.0.0.10` | Şirketin herkese açık internet sitesi (port 80/443) |
| 🔤 **DNS sunucusu** | `10.0.0.53` | Alan adı çözümleme servisi (port 53) |
| 🔑 **SSH sunucusu** | `10.0.0.20` | Yöneticinin uzaktan bağlandığı makine (port 22) — **asıl hedef: bunu dışarıdan tamamen kapalı tutmak** |
| 🗄️ **Veritabanı** | `10.0.0.30` | Müşteri verilerinin tutulduğu, en kritik, en çok korunması gereken makine (port 3306) |
| 😈 **Saldırgan** | `198.51.100.66` | İnternetten gelen, hiç güvenilmeyen taraf |
| 🏢 **Ofis ağı** | `203.0.113.0/24` | Şirket çalışanlarının bağlandığı, güvenilir sayılan ağ bloğu |

> "Şimdi aynı altı karakterle sekiz farklı 'ne olurdu' sorusuna bakacağız."

---

## 4. Canlı gösterim — Web arayüzü (5:15 – 14:00) — ~8.5 dakika

Senaryo seçiciden geçerken her birinde önce **tek cümlelik gerçek hayat çerçevesi**, sonra **1 saldırı butonuna tıkla**, sonucu **Canlı karar akışı** ve **topoloji**den oku. Aşağıdaki her alt başlıkta önce "**Bu ne demek?**" kısmını oku/söyle, sonra adımları uygula.

### 4.1 Senaryo 1 — Açık firewall (baseline) — 1 dk

**Bu ne demek?** Hayal et: şirket daha yeni kuruldu, **henüz hiçbir firewall kuralı yazılmamış**, varsayılan politika da ALLOW. Yani internetten gelen *her* paket, *her* porta, *hiç sorgusuz* ulaşabiliyor. Bu bizim **kontrol grubumuz (baseline)** — "hiç koruma olmasaydı ne olurdu?" sorusunun cevabı. Gerçek hayatta hiçbir şirket bunu yapmaz; bunu sadece karşılaştırma için gösteriyoruz.

- Senaryo seçiciden **"1 - Açık firewall"**'ı seç.
- **Port taraması** butonuna tıkla. *(Bu, saldırganın "bu makinede hangi kapılar açık?" diye 1'den başlayarak bütün portlara tek tek paket göndermesidir — bkz. [KAVRAMLAR.md §13](KAVRAMLAR.md).)*
- Göster: 150/150 paket **yeşil** geçti. "Filtre yok, hiçbir şey durdurulmuyor — saldırgan hangi portun açık olduğunu tamamen öğrenebildi."

### 4.2 Senaryo 2 — Web sunucusu, implicit deny — 1.5 dk

**Bu ne demek?** Şimdi şirket aklını başına topladı: "Sadece müşterilerin kullanması gereken şeyler açık olsun: web sitesi (80/443) ve DNS (53). Uygulama sunucusunun veritabanına konuşması da gerekiyor, o da açık kalsın. **Gerisi — özellikle SSH yönetim portu — dışarıdan tamamen kapalı olsun.**" Bu, gerçek dünyada **her sunucunun olması gereken minimum, makul firewall yapılandırması.**

- Senaryoyu **"2 - Web sunucusu"** yap.
- **Port taraması**'nı tekrar tıkla → bu sefer 148/150 **kırmızı**. Bu 148'in tamamı **implicit deny** — çünkü tarama hep Web sunucusunun (10.0.0.10) portlarına gidiyor ve kural listesinde o IP için sadece 80/443 tanımlı, gerisi için hiç kural yok.
- Paket üretecine git: Hedef IP'yi SSH sunucusu yap (`10.0.0.20`), hedef portu **22** yap, **Paketi gönder**'e bas → DENY.
- **Kural izi** panelini aç: bu sefer en alttaki `deny tcp any any 10.0.0.20 22` kuralının **EŞLEŞTİ** yazdığını göreceksin — implicit deny değil, **açıkça yazılmış bir ACL kuralı**.
- "İki DENY de var ama sebepleri farklı: port taramasındakiler hiçbir kurala uymadığı için varsayılan politikaya (implicit deny) düşüyor; SSH'e gönderdiğim paket ise açıkça yazılmış bir 'SSH'i kapat' kuralına çarpıyor."

### 4.3 Senaryo 3 — SSH bastion, aynı port farklı kaynak — 1.5 dk

**Bu ne demek?** Şirket SSH'i tamamen kapatmak istemiyor — sistem yöneticisinin uzaktan bağlanabilmesi lazım. Ama "herkese açık SSH" de güvensiz. Çözüm: **"SSH sadece ofis ağından (203.0.113.0/24) gelen bağlantılara açık olsun, internetin geri kalanına kapalı kalsın."** Buna gerçek dünyada **"bastion host" / IP tabanlı erişim kısıtlama** denir — aynı kapı, ama sadece belirli bir mahalleden gelenlere açık.

- Senaryoyu **"3 - SSH bastion"** yap.
- Paket üretecinde hedef IP `10.0.0.20`, hedef port **22**; kaynak IP önce **203.0.113.9** (ofis ağının içinden bir IP) gönder → **ALLOW**.
- Sonra kaynak IP'yi **198.51.100.66** (saldırgan) yap, aynı paketi gönder → **DENY**.
- "Aynı hedef, aynı port, aynı protokol — tek fark kaynak IP'nin hangi CIDR bloğunda olduğu. Yöneticinin evden/ofisten bağlanması serbest, ama internetteki herhangi biri SSH'e hiç dokunamıyor."

### 4.4 Senaryo 4 — DMZ / network separation — 1 dk

**Bu ne demek?** Şirketin web sunucusu internete açık olduğu için bir gün **ele geçirilebilir** (hacklenebilir) diye düşünelim. Eğer o ele geçirilen web sunucusu doğrudan veritabanına bağlanabiliyorsa, saldırgan tek adımda müşteri verilerine ulaşır. Bu yüzden mimariye bir kural daha eklendi: **"Web sunucusu (DMZ) veritabanına asla doğrudan konuşamaz; veritabanına sadece arada bir uygulama sunucusu konuşabilir."** Bu senaryo, web sunucusunun **ele geçirilmiş gibi davranıp** veritabanına sızmaya çalıştığı anı simüle ediyor.

- Senaryoyu **"4 - Katmanlı / DMZ"** yap.
- **DMZ → DB** saldırı butonuna tıkla *(bu, web sunucusunun IP'sinden veritabanına doğrudan bağlanma denemesidir)* → engellenir (kırmızı patlama DB düğümünde).
- "Web sunucusu ele geçirilmiş gibi düşünün — yine de veritabanına sıçrayamıyor, çünkü aradaki kural bunu özellikle yasaklıyor. Sadece belirlenmiş uygulama sunucusu (10.0.0.25) veritabanıyla konuşabiliyor."

### 4.5 Senaryo 6 — Stateful inspection — 1.5 dk

**Bu ne demek?** Şirketin iç ağındaki bir çalışan bilgisayarının **dışarı** (internete) HTTPS ile bağlanmasına izin verdik — örneğin bir web sitesini ziyaret etmek için. Ama o dış sitenin **cevap paketleri** de firewall'dan geçmesi gerekiyor. Eğer firewall her paketi hafızasız değerlendiriyorsa, "dışarıdan gelen bu cevaba izin ver" diye ayrı bir kural yazmadığımız sürece o **meşru cevap bile engellenir.** Stateful inspection bu sorunu, "zaten izin verdiğim bir bağlantının devamını hatırlayarak" çözüyor.

- Senaryoyu **"6 - Stateful inspection"** yap, **Stateful** anahtarının açık olduğunu göster.
- Paket üretecinde: iç ağdan dışa `10.0.0.42:51515 → 93.184.216.34:443 [SYN]` gönder (*iç ağdaki bir çalışanın dış bir web sitesine bağlanması*) → ALLOW.
- **Yanıtı gönder ↺** butonuna bas → dönüş paketi (*web sitesinin cevabı*) de ALLOW (stateful tablo sayesinde, kural olmadan).
- Şimdi **Stateful**'ü kapat, aynı dönüş paketini tekrar gönder (elle, SYN ACK, ters yön) → **DENY**.
- "Stateful kapalıyken kendi izin verdiğimiz bağlantının cevabı bile engelleniyor — temel paket filtrelemenin hafızasız olduğunun canlı kanıtı."

### 4.6 Senaryo 7 — Flood guard: sel vs DDoS farkı — 1.5 dk

**Bu ne demek?** Şirket, web sitesine (80/443) normal ziyaretçi trafiğine izin veriyor ama birinin **saniyede 30'dan fazla** istek gönderip sunucuyu/firewall'u yormasını istemiyor — buna karşı bir hız sınırı (flood guard) koydu. Şimdi iki farklı saldırganı karşılaştıracağız: **tek kişilik bir saldırgan** ile **yüzlerce sahte kimlikli bir saldırgan ordusu (botnet/DDoS)**.

- Senaryoyu **"7 - Flood guard"** yap.
- **SYN seli** butonuna tıkla *(tek bir saldırgan IP'sinden art arda bağlantı isteği)* → çoğu paket kırmızı (120/150 engellenir), sayaçta "Flood guard" artışını göster.
- **DDoS (botnet)** butonuna tıkla *(aynı saldırı ama yüzlerce farklı, sahte kaynak IP'den)* → bu sefer **160/160 geçer**.
- "Hız sınırı kaynak IP başınadır. Tek kaynaklı saldırganı durduruyor ama saldırgan kimliğini (IP'sini) her seferinde değiştirirse — yani dağıtık saldırırsa — **bu koruma tek başına yetersiz kalıyor.** Gerçek dünyada bu yüzden DDoS koruması ayrı, daha büyük bir konu."

### 4.7 Senaryo 8 — Kural sırası tuzağı + Lint — 1 dk

**Bu ne demek?** Bir sistem yöneticisi, bir gün hızlıca test yapmak için **geçici olarak "her şeye izin ver"** kuralını en üste ekledi ve **silmeyi unuttu**. Altında hâlâ "SSH'i dışarıya kapat" kuralı duruyor — ama artık hiç çalışmıyor, çünkü üstteki kural her paketi zaten yakalıyor. Bu, gerçek dünyada firewall yönetiminde **en sık yapılan, en tehlikeli insan hatasıdır.**

- Senaryoyu **"8 - Hatalı kural sırası"** yap.
- Kural listesinde `#1 allow any any` kuralının üstte olduğunu göster, altındaki `deny ... 22` kuralının yanındaki **⚠ lint rozetine** gelip tooltip'i oku: *"asla çalışmaz."*
- "Yönetici SSH'i kapattığını sanıyor ama aslında hâlâ herkese açık — çünkü üstteki unutulmuş kural onu gölgeliyor. Statik analiz (lint) bu tür hataları, hiçbir paket göndermeden, sadece kural listesine bakarak otomatik yakalıyor."

---

## 5. Kod ve altyapı turu (14:00 – 17:00) — ~3 dakika

- **`$ iptables`** çekmecesini aç: "Aynı kural listesi, gerçek Linux komutlarına birebir çevriliyor." 2-3 satır oku.
- **`</> Kaynak kod`** çekmecesini aç, **`rules.py`** sekmesine geç, `mismatches()` fonksiyonunu göster: "Bir kuralın bir paketle eşleşip eşleşmediğine karar veren tüm mantık burada, 35 satır."
- `engine.py` sekmesine geç, `evaluate()`'i göster: "Flood guard → stateful → kurallar → varsayılan politika. Firewall'un tüm beyni bu fonksiyon."
- "Web arayüzü, terminal ve PCAP okuyucu — üçü de bu **aynı** fonksiyonu çağırıyor. Gösteriş için ayrı, mantık için tek kod."

---

## 6. Terminal turu (17:00 – 19:00) — ~2 dakika

İkinci terminale geç:

```bash
python3 run.py trace --scenario bastion --src 198.51.100.66 --dst 10.0.0.20 --dport 22
```
"Kural kural, hangi alanın uyduğunu/uymadığını satır satır gösteriyor — tam da az önce arayüzde gördüğümüz 'Kural izi' panelinin terminal hâli."

```bash
python3 run.py lint --scenario messy
```
"Az önceki o tuzak kuralı statik analiz yakalıyor: 'asla çalışmaz' uyarısı."

(Zaman kalırsa) `python3 run.py quiz` ile hızlıca 1 soru çöz: "Kendimi de test etmek için bir quiz modu yazdım."

---

## 7. Kapanış (19:00 – 20:00) — ~1 dakika

**Dürüst sınırlamalar** (DNS tüneli saldırısına köprü kur — bunu canlı göstermediysen bile sözle değinmek güçlü durur):
> "Bu motor sadece IP/port/protokole bakıyor, paketin içeriğini okumuyor. Bu yüzden port 53 (DNS) açık olduğu sürece, biri bu kanalı veri sızdırmak için kötüye kullansa motor bunu **göremez** — çünkü sadece zarfa bakıyor, mektubun içine değil. Gerçek çözüm kitaptaki **application proxy firewall** kavramı, bizim kapsamımızın dışında."

Kapanış cümlesi:
> "Özetle: implicit deny, stateful inspection, flood guard ve DMZ ayrımı — kitabın 10. bölümündeki dört temel kavramı, aynı hayali şirket üzerinden, gerçek kod ve 43 birim testiyle elle tutulur hâle getirdim. Sorularınızı alabilirim."

---

## 🎯 Zaman çizelgesi özeti

| Dakika | Bölüm |
|---|---|
| 0:00–1:00 | Açılış kancası |
| 1:00–4:30 | Teori (5 kavram) |
| 4:30–5:15 | Sahne haritası (kim kim?) |
| 5:15–14:00 | Canlı senaryolar (1, 2, 3, 4, 6, 7, 8) |
| 14:00–17:00 | Kod turu + iptables çıktısı |
| 17:00–19:00 | Terminal turu (trace, lint, quiz) |
| 19:00–20:00 | Sınırlamalar + kapanış |

## ⚠️ Riskler / yedek plan

- **Port doluysa:** `python3 run.py --port 9000 --no-browser` ile önceden test et.
- **Canlı demo donarsa:** `Sıfırla` butonuna bas, senaryoyu yeniden seç.
- **Zaman daralırsa** ilk atlanacak bölüm: 4.7 (lint tuzağı) ve terminal turundaki quiz — temel akış (sahne haritası + 4.1–4.6 + kapanış) 13 dakikada bitirilebilir.
- **Zaman artarsa** eklenecek: `python3 run.py demo --step` ile tüm 7 bölümlük terminal hikayesini adım adım göster.
- **Biri "neden bu kadar çok buton var?" diye sorarsa:** "Çünkü bu bir laboratuvar — her buton bir deney. Ama hepsini aynı anda kullanmıyoruz, her senaryoda sadece 1-2 butona basıyoruz." Yani arayüzü tek seferde açıklamaya çalışma; her senaryoda **sadece o an kullandığın paneli** işaret et.

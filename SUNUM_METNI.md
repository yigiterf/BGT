# 🎙️ Sunum Metni (Final) — MiniFirewall Lab

Bu dosya artık **okuyup doğrudan konuşabileceğin, iki parçalı nihai sunum metnidir.**

- **Kısım 1 — Slayt açıkken konuşacağın metin** (teorik giriş, ~3-4 dk, kelimesi kelimesine okunabilir)
- **Kısım 2 — Slaytı kapatıp web arayüzünü açtığın kısım** (canlı gösterim, adım adım, hangi butona basacağını ve ekranda ne göreceğini söyleyen yönlendirmeli bir rehber)

> Not: [KAVRAMLAR.md](KAVRAMLAR.md) terimleri çok daha detaylı anlatır, [SUNUM_AKISI.md](SUNUM_AKISI.md) zamana bölünmüş bir prova planıdır. Bu dosya ikisinin yerini alan, **sahnede elinde tutacağın nihai metin.**

---

# 📖 KISIM 1 — Slayt açıkken konuşulacak kısım (~3-4 dk)

*(Bunu slaytlar açıkken, kelimesi kelimesine veya kendi cümlelerinle okuyabilirsin. Aşağıdaki metin, senin yazdığın taslağın tamamlanmış/düzeltilmiş hâlidir.)*

> Bizim projemiz bir **firewall simülasyonu**dur.
>
> **Firewall nedir?** Bir ağa giren ve çıkan her paketi inceleyip, "bu paket geçsin mi, engellensin mi?" kararını veren bir sistemdir — bir yazılım olarak da düşünebiliriz.
>
> Peki bu kararı verirken firewall'un baktığı şey nedir? **Paket.** Paket nedir? İki bilgisayar internet üzerinden konuştuğunda aralarında gidip gelen küçük veri birimine paket denir. Bunu küçük bir zarf gibi düşünebiliriz: üzerinde kimden kime gittiği yazan, içinde de biraz veri taşıyan bir zarf.
>
> Peki bu zarfın üzerinde, yani pakette ne bulunur?
>
> - **Hem kaynağın hem hedefin IP adresleri** — IP adresi, internete bağlı bir cihazın tek ve benzersiz adresidir; postadaki açık adres gibi düşünebiliriz.
> - **Protokol bilgisi, TCP vs.** — Protokol, verinin hangi kurallara göre gönderileceğini belirler; TCP garantili ve sıralı bir iletim sağlar, UDP ise daha hızlı ama garantisiz bir iletim sağlar.
> - **Kaynağın ve hedefin portu** — Port, aynı IP adresi üzerinde hangi servise/programa gidileceğini belirten bir numaradır; örneğin 443 numaralı port web sitesinin şifreli halini, 22 numaralı port uzaktan yönetim bağlantısını temsil eder.
> - **Bayrak bilgisi (SYN, ACK vs.)** — Bayraklar, bir TCP bağlantısının hangi aşamada olduğunu belirtir; örneğin SYN bayrağı "ben bu bağlantıyı yeni başlatmak istiyorum" anlamına gelir.
>
> Kısacası paketler bu şekilde. Firewall bu paketlerin dışarıdan içeriye girip giremeyeceğine karar verir demiştik. Bunu yaparken **"paket filtreleme"** yöntemini kullanır. Nedir bu paket filtreleme? Elimizde bir **kural listesi** olur; bu listedeki kurallar, farklı durumlara veya farklı ağ mimarilerine göre değişiklik gösterebilir. Firewall, gelen her paketi bu kurallarla sırayla karşılaştırır ve kabul eder ya da reddeder.
>
> Sonuç olarak bir firewall, temelde bu şekilde çalışır. Şimdi bunu teoride anlatmayı bırakıp, gerçekten çalışan bir sistem üzerinde, canlı olarak göstereceğim.

*(Burada slaytı kapat, web arayüzüne geç.)*

---

# 🖥️ KISIM 2 — Slayt kapalı, canlı gösterim

Bu kısımda artık konuşma metni değil, **sana ne yapacağını adım adım söyleyen bir yönerge** var. Ekranı paylaşıp sırayla uygula; tırnak içindeki cümleleri söyleyebilirsin, geri kalanı senin için yönlendirme.

## 2.0 Arayüzü açtığında ilk söyleyeceğin şey

```bash
python3 run.py
```

Tarayıcı açılınca, hiçbir şeye tıklamadan önce şunu söyle:

> "Bu ekran, az önce anlattığım firewall mantığının çalışan hâli. Dört bölgesi var: solda paketleri/saldırıları ben tetikliyorum, ortada paketlerin firewall'dan geçip geçmediğini canlı görüyoruz, sağda firewall'un kural listesi duruyor, altta ise her kararın kaydı akıyor. Şimdi bu ekranın neyi temsil ettiğini anlatayım."

## 2.1 Ortadaki panel: sahnedeki kim kim?

Ortadaki "CANLI" panelinde (topoloji animasyonunun olduğu yer) **solda üç kaynak, sağda dört hedef** var. Bunları işaret ederek tek tek açıkla:

**Sağ taraf (hedefler — şirketin sunucuları):**

| Ekranda yazan | IP | 1-2 cümlelik açıklama |
|---|---|---|
| **Web** | 10.0.0.10 | "Şirketin internet sitesinin çalıştığı sunucu. Normal portları 80 ve 443." |
| **DNS** | 10.0.0.53 | "Alan adlarını IP adresine çeviren servis. Port 53'ü kullanır." |
| **SSH** | 10.0.0.20 | "Sistem yöneticisinin sunucuya uzaktan, komut satırından bağlandığı servis. Port 22. Bu, dışarıya **en kapalı tutulması gereken** porttur." |
| **DB** | 10.0.0.30 | "Veritabanı sunucusu — şirketin en kritik, en çok korunması gereken verisi burada. Port 3306." |

**Sol taraf (kaynaklar — paketleri kim gönderiyor):**

| Ekranda yazan | IP | 1-2 cümlelik açıklama |
|---|---|---|
| **SALDIRGAN** | 198.51.100.66 | "İnternetten gelen, hiç güvenmediğimiz taraf. Bütün saldırı senaryolarında paketleri gönderen bu." |
| **OFİS AĞI** | 203.0.113.0/24 | "Şirket çalışanlarının bağlandığı, güvenilir sayılan ağ bloğu. `/24` demek, bu bloktaki 256 IP'nin tamamı demek." |
| **İÇ AĞ** | 10.0.0.0/24 | "Şirketin kendi iç ağı — yani şirketin sunucularının birbiriyle veya dışarıyla konuştuğu taraf; stateful senaryoda bunu kullanacağız." |

> Söyleyeceğin özet cümle: "Yani sahnemizde sabit bir kurgu var: bir şirket ağı, o şirketin dört servisi, bir de dışarıdan gelen saldırgan ve güvenilir ofis ağı. Şimdi bu şirketin firewall kurallarını sekiz farklı şekilde yapılandırırsak ne olur, onu göstereceğim."

## 2.2 Üstteki "SENARYO" menüsü — 8 senaryo tek tek ne demek?

Üstteki `SENARYO ▾` menüsünü aç, göster, ve her birini **1-2 cümleyle** şöyle tanıt (henüz hiçbirini seçme, sadece listeyi göster):

| # | Menüdeki adı | 1-2 cümlelik tanıtım |
|---|---|---|
| 1 | **Açık firewall** | "Hiç kural yok, her şeye izin var. Hiç koruma olmasaydı ne olurdu — bunun karşılaştırma noktası." |
| 2 | **Web sunucusu** | "Gerçekçi, temel bir yapılandırma: sadece web, DNS ve uygulama→veritabanı açık, SSH dışarıya kapalı." |
| 3 | **SSH bastion** | "SSH tamamen kapalı değil, ama sadece ofis ağından bağlanılabiliyor — internetin geri kalanına kapalı." |
| 4 | **Katmanlı / DMZ** | "Web sunucusu ile veritabanı arasına da bir kural kondu: web sunucusu ele geçirilse bile veritabanına sıçrayamıyor." |
| 5 | **Saldırı altında** | "Belirli bir saldırgan IP'si, hangi portu denerse denesin, tamamen ve otomatik engelleniyor." |
| 6 | **Stateful inspection** | "Firewall, izin verdiği bağlantıları hatırlıyor; dönüş paketlerini ayrı bir kural yazmadan geçiriyor." |
| 7 | **Flood guard** | "Bir kaynağın saniyede çok fazla paket göndermesine karşı hız sınırı var — ama bu sınırın bir zayıflığı olacak." |
| 8 | **Hatalı kural sırası** | "Yönetici bir hata yapmış: unutulmuş geniş bir kural, altındaki güvenlik kuralını tamamen işe yaramaz hale getiriyor." |

> "Şimdi bu sekiz senaryoyu tek tek seçip, her birinde soldaki saldırı butonlarından uygun olanına basacağım ve sonucu birlikte okuyacağız."

---

## 2.3 Senaryo senaryo: hangi butona bas, ne göreceksin, kuralları nasıl okuyacaksın

Her blokta dört şey var: **Seç** (hangi senaryoyu/butonu seçeceksin), **Gör** (ekranda tam olarak ne göreceksin, rakamlarıyla), **Oku** (kural listesini/izini nasıl yorumlayacaksın), **Söyle** (söyleyebileceğin cümle). Tüm rakamlar koddan çalıştırılarak doğrulandı, ezbere değil.

---

### ① Senaryo 1 — Açık firewall

**Seç:**
1. Üstteki `SENARYO` menüsünden **"1 - Açık firewall"**'ı seç.
2. Sol paneldeki **SALDIRI SENARYOLARI** bölümünden **"Port taraması"** butonuna tıkla.

**Gör:** Ortadaki ekranda 150 paketin hepsinin **yeşil** çizgilerle Web sunucusuna ulaştığını göreceksin. Alttaki istatistik şeridinde `Toplam 150`, `Geçen 150`, `Engellenen 0` yazacak.

**Oku:** Sağdaki **Kurallar** paneli tamamen **boş** olacak (0 kural) — çünkü bu senaryoda hiç kural yazılmamış. Ortadaki karta tıklayıp **"Kural izi"** butonuna basarsan (bir paket gönderdikten sonra aktifleşir), açılan pencerede hiç kural satırı görmeyeceksin, direkt "Hiçbir kural eşleşmedi → varsayılan politika ALLOW" yazısını göreceksin.

**Söyle:** "Filtre yok, hiçbir şey durdurulmuyor — saldırgan hangi portun açık olduğunu tamamen öğrenebildi. Bunu az sonraki senaryolarla karşılaştıracağız."

---

### ② Senaryo 2 — Web sunucusu (temel ACL + implicit deny)

**Seç:**
1. `SENARYO` menüsünden **"2 - Web sunucusu"**'nu seç.
2. **"Port taraması"** butonuna tekrar bas.

**Gör:** Bu sefer çoğu paket **kırmızı**. İstatistik şeridinde `Toplam 150`, `Geçen 2`, `Engellenen 148` yazacak. Sadece 80 ve 443 portlarına giden iki paket yeşil geçecek.

**Oku:** Sağdaki **Kurallar** panelinde `allow ... 80` ve `allow ... 443` satırlarının altındaki ince çubuğun diğerlerine göre dolu olduğunu göreceksin (eşleşme oldu). Engellenen 148 paketin hiçbiri aslında **hiçbir kurala uymuyor** — kural listesinde Web sunucusunun diğer portlarına dair hiçbir satır yok, bu yüzden hepsi **varsayılan politikaya (implicit deny)** düşüyor.

> **Ekstra adım (açık ACL kuralını göstermek için):** Sol paneldeki **Paket Üreteci** formuna geç. **Hedef IP** kutusuna `10.0.0.20` (SSH sunucusu), **Hedef Port** kutusuna `22` yaz, **Paketi gönder**'e bas. Sonuç yine DENY ama bu sefer **farklı bir sebeple** — "Kural izi"ni açtığında en alttaki `deny tcp any any 10.0.0.20 22` satırının **"EŞLEŞTİ"** yazdığını göreceksin. Bu, varsayılan politikadan değil, **açıkça yazılmış bir yasak kuraldan** kaynaklanıyor.

**Söyle:** "Port taramasındaki 148 ret, hiçbir kuralın karşılamadığı — yani varsayılan politikanın devreye girdiği — paketler. Ama SSH'e özel gönderdiğim paket farklı: orada açıkça yazılmış bir 'SSH'i kapat' kuralı var. İkisi de DENY sonucu veriyor ama sebepleri farklı — biri implicit deny, diğeri açık bir ACL kuralı."

---

### ③ Senaryo 3 — SSH bastion (aynı port, farklı kaynak IP)

**Seç:**
1. `SENARYO` menüsünden **"3 - SSH bastion"**'u seç.
2. Önce sol paneldeki **"SSH brute force"** butonuna bas.

**Gör:** 60 paketin **hepsi kırmızı** (60/60 engellendi). Saldırgan SSH'e bağlanmaya çalışıyor ama hiçbiri geçmiyor.

**Oku:** Kural izi'ni açarsan, hiçbir kuralın eşleşmediğini, varsayılan politika DENY'in devreye girdiğini göreceksin — çünkü SSH kuralı sadece ofis ağına özel, saldırganın IP'si o ağda değil.

3. Şimdi **Paket Üreteci** formuna geç: **Kaynak IP** kutusuna `203.0.113.9` (ofis ağından bir IP), **Hedef IP**'ye `10.0.0.20`, **Hedef Port**'a `22` yaz, **Paketi gönder**'e bas.

**Gör:** Bu sefer **ALLOW** — yeşil.

**Oku:** Kural izi'nde ilk kuralın (`allow tcp 203.0.113.0/24 any 10.0.0.20 22`) EŞLEŞTİ yazdığını göreceksin.

**Söyle:** "Aynı hedef, aynı port, aynı protokol — tek fark kaynağın hangi IP bloğundan geldiği. Saldırgan internetten hiç giremiyor, ama ofisten bağlanan biri sorunsuz giriyor. Bu, IP tabanlı erişim kısıtlamasının canlı kanıtı."

---

### ④ Senaryo 4 — Katmanlı / DMZ (ağ ayırma)

**Seç:**
1. `SENARYO` menüsünden **"4 - Katmanlı / DMZ"**'yi seç.
2. Sol paneldeki **"DMZ → DB"** butonuna bas.

**Gör:** Tek bir paket gönderilir, ortada **kırmızı** bir patlama görürsün — web sunucusundan veritabanına giden paket firewall'da durduruluyor.

**Oku:** Kural izi'ni açarsan en üstteki kuralın (`deny tcp 10.0.0.10 any 10.0.0.30 3306 # DMZ → DB YASAK`) EŞLEŞTİ yazdığını göreceksin — bu açıkça yazılmış bir yasak kural, implicit deny değil.

**Söyle:** "Bu paket, web sunucusunun kendisinden gönderiliyormuş gibi kurgulandı — yani web sunucusu ele geçirilmiş gibi düşünün. Yine de veritabanına sıçrayamıyor, çünkü aradaki kural bunu özellikle yasaklıyor. Sadece belirlenmiş bir uygulama sunucusu (10.0.0.25) veritabanıyla konuşabiliyor."

---

### ⑤ Senaryo 5 — Saldırı altında (kademeli savunma)

**Seç:**
1. `SENARYO` menüsünden **"5 - Saldırı altında"**'yı seç.
2. **"Port taraması"** butonuna tekrar bas (aynı buton, Senaryo 1'de kullandığın).

**Gör:** 150 paketin **hepsi kırmızı** (150/150 engellendi) — Senaryo 1'deki tam tersi.

**Oku:** Kural izi'ni açarsan, **ilk kuralın** (`deny tcp 198.51.100.66/32 any any any # Saldırganı kes`) her paket için EŞLEŞTİ yazdığını göreceksin — saldırganın hangi portu denediğinin hiç önemi yok, IP'si zaten tamamen yasaklı.

**Söyle:** "Az önce aynı butonla, Senaryo 1'de bu saldırı 150/150 geçmişti. Şimdi aynı saldırı, aynı buton — ama bu sefer sıfır paket geçiyor. Fark, bu sefer bir yöneticinin saldırgan IP'sini tespit edip tek bir kuralla tamamen kapatmış olması. Gerçek dünyada saldırı anında yapılan ilk müdahale genelde budur."

---

### ⑥ Senaryo 6 — Stateful inspection

Bu senaryo **buton değil, manuel paket** ile gösteriliyor — biraz daha fazla adım var, dikkatli ilerle.

**Seç:**
1. `SENARYO` menüsünden **"6 - Stateful inspection"**'ı seç. Üstteki **Stateful** anahtarının **açık** olduğunu kontrol et.
2. **Paket Üreteci**'ne şunları yaz: Kaynak IP `10.0.0.42`, Kaynak Port `51515`, Hedef IP `93.184.216.34`, Hedef Port `443`, Protokol `TCP`, Bayrak `SYN`. **Paketi gönder**.

**Gör:** **ALLOW** (yeşil) — "iç ağdaki bir çalışanın dışarıdaki bir web sitesine bağlanması" gibi düşün.

3. Verdict kartının yanında artık **"Yanıtı gönder ↺"** butonu belirecek. Ona tıkla.

**Gör:** Bu, az önce giden paketin **ters yönü** (web sitesinden gelen cevap) — sonuç yine **ALLOW**.

**Oku:** Kural izi'ni açarsan "Stateful tablo: bu paket izin verilmiş bir oturumun devamı → ALLOW" yazdığını göreceksin; kural listesine hiç bakılmadı.

4. Şimdi üstteki **Stateful** anahtarını **kapat**. **"Yanıtı gönder ↺"**'e tekrar bas (ya da aynı ters yönlü paketi Paket Üreteci'nden elle gir: Kaynak IP `93.184.216.34`, Kaynak Port `443`, Hedef IP `10.0.0.42`, Hedef Port `51515`, Bayrak `SYN ACK`).

**Gör:** Bu sefer **DENY** (kırmızı) — aynı paket, farklı sonuç.

**Söyle:** "Stateful açıkken, firewall az önce izin verdiği bağlantıyı hatırlıyor ve cevabını otomatik geçiriyor. Kapattığımda ise aynı cevap paketi engelleniyor — çünkü kural listesinde 'dışarıdan gelen cevaplara izin ver' diye bir satır yok. Bu, temel paket filtrelemenin hafızasız olduğunun canlı kanıtı."

---

### ⑦ Senaryo 7 — Flood guard: sel vs DDoS

**Seç:**
1. `SENARYO` menüsünden **"7 - Flood guard"**'ı seç.
2. **"SYN seli"** butonuna bas.

**Gör:** 150 paketten büyük bir kısmı **kırmızı** — istatistik şeridinde `Flood engeli` sayacının hızla arttığını göreceksin.

**Oku:** Kural izi'ni açarsan ilk birkaç paketin kural listesine bakmadan direkt "Flood guard: ... saniyede 30 paket sınırını aştı → DENY" ile engellendiğini göreceksin — bu, kural listesinden bile önce devreye giren bir kontrol.

3. Şimdi **"DDoS (botnet)"** butonuna bas.

**Gör:** Bu sefer paketlerin **hepsi yeşil** geçiyor — `Toplam 160`, `Geçen 160`, `Engellenen 0`.

**Söyle:** "Aynı hedefe, aynı sayıda paket gönderdim ama bu sefer yüzlerce farklı sahte kaynak IP'den. Hız sınırı IP başına çalıştığı için, her sahte IP kendi başına limitin çok altında kalıyor ve hiçbiri yakalanmıyor. Bu, 'hız sınırlama tek başına dağıtık saldırıyı durduramaz' gerçeğinin canlı kanıtı."

---

### ⑧ Senaryo 8 — Hatalı kural sırası (tuzak!)

**Seç:**
1. `SENARYO` menüsünden **"8 - Hatalı kural sırası"**'nı seç.
2. Sağdaki **Kurallar** panelini göster: en üstte `allow tcp any any any any # 'Geçici' her şeye izin (UNUTULDU)`, hemen altında `deny tcp any any 10.0.0.20 22 # SSH yasağı (asla çalışmaz!)` yazıyor. İkinci kuralın yanındaki **⚠ rozete** fareyle gel, tooltip'te "asla çalışmaz" yazdığını göster.
3. Sol paneldeki **"SSH brute force"** butonuna bas.

**Gör:** 60 paketin **hepsi yeşil** (60/60 **ALLOW**) — yöneticinin "SSH'i kapattım" sandığı yer, aslında tamamen açık.

**Oku:** Kural izi'ni açarsan **ilk kuralın** (`allow tcp any any any any`) EŞLEŞTİ yazdığını göreceksin — ikinci satırdaki (`deny ... 22`) kurala sıra hiç gelmiyor, çünkü "ilk eşleşen kazanır" ve bu paket zaten ilk kuralda yakalanıyor.

**Söyle:** "Yönetici SSH'i kapattığını sanıyor çünkü deny kuralı kural listesinde duruyor — ama aslında hiç çalışmıyor çünkü üstünde unutulmuş, çok geniş bir izin kuralı var. 60 tane şifre denemesinin hepsi içeri giriyor. Statik analiz (lint) bu tür hataları, hiç paket göndermeden, sadece kural listesine bakarak önceden yakalayabiliyor — az önce gördüğünüz uyarı rozeti bunun kanıtı."

---

## 2.4 Hızlı referans tablosu (kendine not)

| Senaryo | Buton/İşlem | Sonuç | Ne gösteriyor |
|---|---|---|---|
| 1. Açık firewall | Port taraması | 150/150 ALLOW | Koruma yoksa her şey geçer |
| 2. Web sunucusu | Port taraması + manuel SSH paketi | 148/150 DENY (çoğu implicit, SSH'i açık ACL) | ACL + implicit deny farkı |
| 3. SSH bastion | SSH brute force + manuel ofis paketi | Saldırgan 60/60 DENY, ofis ALLOW | Kaynak IP'ye göre filtreleme |
| 4. DMZ | DMZ → DB | 1/1 DENY | Network separation |
| 5. Saldırı altında | Port taraması | 150/150 DENY | Tek IP'yi tamamen kesmek |
| 6. Stateful | Manuel paket + Yanıtı gönder ↺ | Stateful açık→ALLOW, kapalı→DENY | Oturum hafızası |
| 7. Flood guard | SYN seli → DDoS | SYN seli çoğu DENY, DDoS 160/160 ALLOW | Hız sınırının sınırı |
| 8. Hatalı sıra | SSH brute force | 60/60 ALLOW (!) | Kural sırası hatası + lint |

---

*İlgili dosyalar: [KAVRAMLAR.md](KAVRAMLAR.md) (terimler sıfırdan), [SUNUM_AKISI.md](SUNUM_AKISI.md) (zaman çizelgeli prova), [PROJE_REHBERI.md](PROJE_REHBERI.md) (kodun içi), [README.md](README.md) (teknik referans).*

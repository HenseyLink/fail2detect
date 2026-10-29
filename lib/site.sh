#!/usr/bin/env bash
# fail2detect — сайт-маскировка для selfsteal (Reality отдаёт «чужих» на свой nginx).
#
# Сканер или человек, открывший домен ноды, должен увидеть обычный сайт
# небольшой компании: несколько страниц, стили, favicon, robots.txt, sitemap
# и настоящий 404 — а не одну страницу-заглушку на любой адрес. Компания,
# отрасль, город и цвета выбираются случайно, поэтому сайты нод не похожи друг
# на друга (и на сайты других установок fail2detect).

F2D_SITE_MARK="f2d-site v2"

_site_pick() { local a=("$@"); echo "${a[RANDOM % ${#a[@]}]}"; }

# сайт сгенерирован старой версией (одна страница «скоро будет»)?
site_is_legacy() { [[ -f "$1/index.html" ]] && ! grep -q "$F2D_SITE_MARK" "$1/index.html" && grep -q 'Our new website is on its way' "$1/index.html"; }

site_generate() {   # каталог [--force]
    local root="$1"
    if [[ -f "$root/index.html" && "${2:-}" != --force ]]; then
        site_is_legacy "$root" || return 0   # свой сайт пользователя или уже наш — не трогаем
    fi
    local kind name tagline city accent year
    kind=$(_site_pick studio consulting logistics cloud)
    city=$(_site_pick "Amsterdam" "Rotterdam" "Hamburg" "Munich" "Vienna" "Prague" "Helsinki" "Tallinn" "Riga" "Warsaw" "Zurich" "Copenhagen")
    accent=$(_site_pick "#2b4acb" "#0f766e" "#9333ea" "#c2410c" "#0369a1" "#be123c" "#4d7c0f")
    year=$(date +%Y)
    local s1 s2 s3 d1 d2 d3 hero lead
    case "$kind" in
        studio)
            name="$(_site_pick Northwind Bluefield Arcadia Lumen Cedar Harbor Juniper Foxglove) $(_site_pick Studio Design Works Lab)"
            tagline="Product design and engineering"
            hero="We design and build digital products people enjoy using."
            lead="A small, senior team helping companies shape, launch and grow web and mobile products — from first sketches to production."
            s1="Product design"; d1="Research, interaction design and design systems that keep products consistent as they grow."
            s2="Web engineering"; d2="Fast, accessible front-ends and pragmatic back-ends, built to be maintained by your own team."
            s3="Growth & analytics"; d3="Instrumentation, experiments and dashboards that show what actually moves the numbers.";;
        consulting)
            name="$(_site_pick Halden Marlow Ashby Kestrel Whitmore Brightwater) $(_site_pick Partners Advisory Consulting Group)"
            tagline="Strategy, operations and technology advisory"
            hero="Clear advice for complex decisions."
            lead="We work alongside leadership teams on strategy, operations and technology — with a focus on measurable results rather than slide decks."
            s1="Strategy"; d1="Market entry, portfolio reviews and growth plans grounded in data and in how your business really works."
            s2="Operations"; d2="Process redesign, cost reviews and supply chain improvements that hold up after we leave."
            s3="Technology"; d3="Architecture reviews, vendor selection and delivery oversight for critical IT programmes.";;
        logistics)
            name="$(_site_pick Nordline Baltic Meridian Trident Polar Crossway) $(_site_pick Logistics Freight Cargo Transport)"
            tagline="Freight forwarding across Europe"
            hero="Reliable freight, from the first mile to the last."
            lead="Road, sea and air freight for manufacturers and retailers, with customs handling and real-time shipment tracking."
            s1="Road freight"; d1="Full and part loads across the EU with dedicated account managers and fixed transit times."
            s2="Sea & air"; d2="Container and air cargo bookings through trusted carriers, door-to-door or port-to-port."
            s3="Customs & warehousing"; d3="Customs clearance, bonded storage and cross-docking in our partner warehouses.";;
        cloud)
            name="$(_site_pick Stratus Ironleaf Cobalt Vantage Nimbus Quartz) $(_site_pick Systems Cloud Hosting Networks)"
            tagline="Managed infrastructure for growing teams"
            hero="Infrastructure that stays out of your way."
            lead="Managed servers, backups and monitoring for software companies that would rather ship features than babysit machines."
            s1="Managed servers"; d1="Provisioning, patching and 24/7 monitoring of dedicated and virtual servers in European data centres."
            s2="Backups & recovery"; d2="Encrypted off-site backups with tested restores and clear recovery time objectives."
            s3="Consulting"; d3="Performance tuning, migrations and capacity planning from engineers who run production every day.";;
    esac
    local slug; slug=$(tr '[:upper:] ' '[:lower:]-' <<<"$name" | tr -cd 'a-z-')
    local mail="hello@${slug%%-*}.$(_site_pick com eu io net)"

    mkdir -p "$root/assets" "$root/about" "$root/services" "$root/contact"
    cat > "$root/assets/site.css" <<EOF
:root{--accent:${accent};--ink:#1d2433;--muted:#5b6475;--line:#e6e8ef;--bg:#f7f8fb}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:#fff}
a{color:var(--accent)}.wrap{max-width:1080px;margin:0 auto;padding:0 24px}
header{border-bottom:1px solid var(--line);background:#fff}
header .wrap{display:flex;align-items:center;justify-content:space-between;height:68px}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;color:var(--ink);text-decoration:none;font-size:18px}
.logo i{width:26px;height:26px;border-radius:7px;background:var(--accent);display:inline-block}
nav a{margin-left:26px;color:var(--muted);text-decoration:none;font-size:15px}nav a:hover,nav a.on{color:var(--ink)}
.hero{background:var(--bg);border-bottom:1px solid var(--line)}.hero .wrap{padding:96px 24px 88px}
h1{font-size:clamp(32px,5vw,52px);line-height:1.1;margin:0 0 18px;letter-spacing:-.02em;max-width:760px}
h2{font-size:28px;margin:0 0 12px;letter-spacing:-.01em}h3{font-size:19px;margin:0 0 8px}
.lead{font-size:19px;color:var(--muted);max-width:640px;margin:0}
.btn{display:inline-block;margin-top:30px;padding:13px 24px;border-radius:9px;background:var(--accent);color:#fff;text-decoration:none;font-weight:600}
section{padding:72px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:22px;margin-top:28px}
.card{border:1px solid var(--line);border-radius:14px;padding:26px;background:#fff}.card p{color:var(--muted);margin:0}
.facts{display:flex;flex-wrap:wrap;gap:44px;margin-top:20px}.facts b{display:block;font-size:30px}.facts span{color:var(--muted);font-size:14px}
.page{padding:64px 0 80px}.page p{color:var(--muted);max-width:720px}
form{display:grid;gap:14px;max-width:520px;margin-top:24px}input,textarea{font:inherit;padding:12px 14px;border:1px solid var(--line);border-radius:9px}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:14px}footer .wrap{display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;padding:30px 24px}
@media(max-width:640px){nav a{margin-left:14px}.hero .wrap{padding:64px 24px}}
EOF
    cat > "$root/favicon.svg" <<EOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="${accent}"/><text x="16" y="22" font-family="Arial,sans-serif" font-size="17" font-weight="700" fill="#fff" text-anchor="middle">${name:0:1}</text></svg>
EOF
    _site_page() {   # файл активный_пункт заголовок_страницы тело
        local nav="" p l
        for p in "/|Home" "/services/|Services" "/about/|About" "/contact/|Contact"; do
            l="${p#*|}"; nav+="<a href=\"${p%%|*}\"$([[ "$l" == "$2" ]] && echo ' class="on"')>$l</a>"
        done
        cat > "$1" <<EOF
<!doctype html>
<!-- ${F2D_SITE_MARK} -->
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$3</title><meta name="description" content="${name} — ${tagline}.">
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/site.css">
</head><body>
<header><div class="wrap"><a class="logo" href="/"><i></i>${name}</a><nav>${nav}</nav></div></header>
$4
<footer><div class="wrap"><span>&copy; ${year} ${name} · ${city}</span><span><a href="mailto:${mail}">${mail}</a></span></div></footer>
</body></html>
EOF
    }
    _site_page "$root/index.html" Home "${name} — ${tagline}" "<div class=\"hero\"><div class=\"wrap\"><h1>${hero}</h1><p class=\"lead\">${lead}</p><a class=\"btn\" href=\"/contact/\">Get in touch</a></div></div>
<section><div class=\"wrap\"><h2>What we do</h2><div class=\"grid\">
<div class=\"card\"><h3>${s1}</h3><p>${d1}</p></div><div class=\"card\"><h3>${s2}</h3><p>${d2}</p></div><div class=\"card\"><h3>${s3}</h3><p>${d3}</p></div>
</div></div></section>
<section style=\"background:var(--bg);border-top:1px solid var(--line)\"><div class=\"wrap\"><h2>Based in ${city}, working across Europe</h2>
<div class=\"facts\"><div><b>$((RANDOM % 12 + 6))</b><span>years in business</span></div><div><b>$((RANDOM % 140 + 60))+</b><span>clients served</span></div><div><b>$((RANDOM % 25 + 8))</b><span>people on the team</span></div></div></div></section>"
    _site_page "$root/services/index.html" Services "Services — ${name}" "<div class=\"page\"><div class=\"wrap\"><h1>Services</h1><p class=\"lead\">${lead}</p><div class=\"grid\">
<div class=\"card\"><h3>${s1}</h3><p>${d1}</p></div><div class=\"card\"><h3>${s2}</h3><p>${d2}</p></div><div class=\"card\"><h3>${s3}</h3><p>${d3}</p></div></div></div></div>"
    _site_page "$root/about/index.html" About "About — ${name}" "<div class=\"page\"><div class=\"wrap\"><h1>About us</h1>
<p>${name} was founded in ${city} by a few people who wanted to do careful, honest work for a small number of clients. We still work that way: one team, direct communication and no unnecessary layers.</p>
<p>We are independent and privately owned. Most of our clients come through recommendations, and many have worked with us for years.</p></div></div>"
    _site_page "$root/contact/index.html" Contact "Contact — ${name}" "<div class=\"page\"><div class=\"wrap\"><h1>Contact</h1>
<p>Tell us a little about your project and we will get back to you within one business day. You can also write to <a href=\"mailto:${mail}\">${mail}</a>.</p>
<form onsubmit=\"this.innerHTML='<p>Thank you — we will be in touch shortly.</p>';return false\"><input placeholder=\"Name\" required><input type=\"email\" placeholder=\"Email\" required><textarea rows=\"5\" placeholder=\"Message\"></textarea><button class=\"btn\" style=\"border:0;cursor:pointer\">Send</button></form></div></div>"
    _site_page "$root/404.html" "" "Page not found — ${name}" "<div class=\"page\"><div class=\"wrap\"><h1>Page not found</h1><p>The page you are looking for does not exist or has been moved.</p><a class=\"btn\" href=\"/\">Back to the homepage</a></div></div>"
    printf 'User-agent: *\nAllow: /\n' > "$root/robots.txt"
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        local u base="${SELFSTEAL_DOMAIN:+https://$SELFSTEAL_DOMAIN}"
        for u in / /services/ /about/ /contact/; do echo "  <url><loc>${base}$u</loc></url>"; done
        echo '</urlset>'
    } > "$root/sitemap.xml"
    chmod -R a+rX "$root"
    SITE_NAME="$name"
}

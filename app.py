from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
import smtplib
import jwt
import hashlib
import secrets
import psycopg2
import psycopg2.extras
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

DATABASE_URL = os.environ.get("DATABASE_URL", "")
GMAIL_USER   = os.environ.get("GMAIL_USER", "")
GMAIL_PASS   = os.environ.get("GMAIL_APP_PASSWORD", "")
REPLY_TO     = os.environ.get("REPLY_TO_EMAIL", "AP3@SeacrestSW.com")
APP_USER     = os.environ.get("APP_USERNAME", "sandra")
APP_PASS_HASH= os.environ.get("APP_PASSWORD_HASH", "")
JWT_SECRET   = os.environ.get("JWT_SECRET", secrets.token_hex(32))

# ── Auth ────────────────────────────────────────────────────────────────────

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def make_token():
    payload = {"sub": APP_USER, "exp": datetime.utcnow() + timedelta(hours=12)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth.split(" ", 1)[1]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if username != APP_USER or hash_password(password) != APP_PASS_HASH:
        return jsonify({"error": "Invalid username or password"}), 401
    return jsonify({"token": make_token(), "ok": True})

# ── Database ────────────────────────────────────────────────────────────────

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS associations (
            tag TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT DEFAULT '',
            manager TEXT DEFAULT '',
            manager_email TEXT DEFAULT '',
            updated_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS vendors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT DEFAULT '',
            sender TEXT DEFAULT 'Sandra',
            gl_exp TEXT DEFAULT '',
            gl_type TEXT DEFAULT 'coi',
            wc_exp TEXT DEFAULT '',
            wc_type TEXT DEFAULT 'coi',
            bl_exp TEXT DEFAULT '',
            bl_type TEXT DEFAULT 'license',
            w9 INTEGER DEFAULT 0,
            tags TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            cois_on_file TEXT DEFAULT '{}',
            created_at TEXT,
            updated_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS email_log (
            id TEXT PRIMARY KEY,
            vendor_id TEXT NOT NULL,
            vendor_name TEXT,
            vendor_email TEXT,
            sent_at TEXT,
            docs_requested TEXT,
            cc_list TEXT
        )
    """)

    conn.commit()

    # Seed associations if empty
    c.execute("SELECT COUNT(*) as cnt FROM associations")
    row = c.fetchone()
    if row["cnt"] == 0:
        seed_associations(c)
        conn.commit()

    conn.close()

def seed_associations(c):
    assocs = [{"tag":"0APM","name":"Arielle At Pelican Marsh Condominium Association, Inc.","address":"Arielle Drive Naples, FL 34109","manager":"Ricardy Joseph","managerEmail":"rjoseph@seacrestsw.com"},{"tag":"0ART","name":"Artesia Naples Master Association, Inc.","address":"1460 Santiago Circle Naples, FL 34113","manager":"Emily Brooks","managerEmail":"artesiamgr@swpropmgt.com"},{"tag":"BFB","name":"Barefoot Beach Property Owners Association, Inc.","address":"195 Barefoot Beach Road Bonita Springs, FL 34134","manager":"Karen Shepard","managerEmail":"office@barefootbeachpoa.org"},{"tag":"BAR","name":"Barrington Club Condominium Association, Inc.","address":"7045-7108 Barrington Circle Naples, FL 34108","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"BFC","name":"Bayfront Condo of Naples, Inc.","address":"401-451 Bayfront Place Naples, FL 34102","manager":"Michael Molineaux","managerEmail":"pmbayfront@swpropmgt.com"},{"tag":"0BCA","name":"Baypoint Condominium Association, Inc.","address":"33 & 35 Bluebill Ave Naples, FL 34108","manager":"Carolyn Sabin","managerEmail":"csabin@swpropmgt.com"},{"tag":"0BSR","name":"Bayshore Ranch Property Owners Association, Inc.","address":"17758 Saddleback Loop North Fort Myers, FL 33917","manager":"James Callahan","managerEmail":"jcallahan@seacrestsw.com"},{"tag":"0BSV","name":"Bayshores of Vanderbilt Beach Condominium Association, Inc.","address":"10475 & 10525 Gulf Shore Boulevard Naples, FL 34108","manager":"Veronica Lee","managerEmail":"Bashoresmgr@seacrestsw.com"},{"tag":"BPC","name":"Bear's Paw Condominium I Association, Inc.","address":"111-1535 Wildwood Lane Naples, FL 34105","manager":"Laura Hartigan","managerEmail":"lhartigan@swpropmgt.com"},{"tag":"0BVPC","name":"Bella Via at Port Charlotte Condominium Association, Inc.","address":"23301 & 23309 Collina Way Port Charlotte, FL 33980","manager":"James Callahan","managerEmail":"jcallahan@seacrestsw.com"},{"tag":"BCP","name":"Bent Creek Preserve Homeowners Association, Inc.","address":"9350 Bronwood Pl Naples, FL 34120","manager":"Bonnie Ash","managerEmail":"bcmanager@swpropmgt.com"},{"tag":"BWV","name":"Bridge-Way Villas Association, Inc","address":"601-677 Bridgeway Lane Naples, FL 34108","manager":"Luke Brooks","managerEmail":"lbrooks@seacrestsw.com"},{"tag":"0CAL","name":"Calais At Pelican Bay Condominium Association, Inc.","address":"7000-7056 Pelican Bay Blvd. Naples, FL 34108","manager":"John Zizzo","managerEmail":"jzizzo@seacrestsw.com"},{"tag":"CFC","name":"Callista at Fiddler's Creek Condominium Association, Inc.","address":"2710 Callista Court Naples, FL 34114","manager":"Ricardy Joseph","managerEmail":"rjoseph@seacrestsw.com"},{"tag":"CSQ","name":"Cambridge Square/Naples Gateway Master Association, Inc.","address":"3585-3645 Gateway Lane Naples, FL 34109","manager":"Janine Curto","managerEmail":"jcurto@swpropmgt.com"},{"tag":"0CAS","name":"Cascada at Fiddler's Creek Condominium Association, Inc.","address":"9002-9114 Cascada Way Naples, FL 34114","manager":"Linda Marcos","managerEmail":"lmarcos@swpropmgt.com"},{"tag":"0CRH","name":"Cascades at River Hall Residents' Association, Inc.","address":"15500 Paradise Palm Blvd Alva, FL 33920","manager":"Colleen Linzy","managerEmail":"CascadesriverhallCAM@outlook.com"},{"tag":"CPC","name":"Castello Professional Center, Inc.","address":"1044 Castello Drive Naples, FL 34103","manager":"Tom Hansen","managerEmail":"thansen@seacrestsw.com"},{"tag":"0CTC","name":"Castillo at Tiburon Condominium Association, Inc.","address":"2825 Tiburon Boulevard East Naples, FL 34109","manager":"Tom Hansen","managerEmail":"thansen@seacrestsw.com"},{"tag":"CPO","name":"Central Park Owners' Association, Inc.","address":"Cypress Terrace Circle Ft. Myers, FL 33907","manager":"Jeff Basik","managerEmail":"jpbafa@aol.com"},{"tag":"0CM","name":"Chanteclair Maisonettes Of Pelican Bay Condominium Association, Inc.","address":"5895-5899 Chanteclair Drive Naples, FL 34108","manager":"John Albright","managerEmail":"jalbright@seacrestsw.com"},{"tag":"0CHAT","name":"Chateaumere Condominium Association, Inc","address":"6000 Pelican Bay Blvd Naples, FL 34108","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"0CHAN","name":"Coach Homes At Artesia Naples Condominium Association, Inc.","address":"1614-1642 Oceania Drive South Naples, FL 34113","manager":"Dierdre Woods","managerEmail":"dwoods@swpropmgt.com"},{"tag":"0CHZ","name":"Coach Homes on Zeno at Esplanade by the Islands Condominium Association, Inc.","address":"15244-15261 Zeno Way Naples, FL 34114","manager":"Janine Curto","managerEmail":"jcurto@swpropmgt.com"},{"tag":"OCV","name":"Concord At The Vineyards Condominium Association, Inc.","address":"155-230 Vintage Circle Naples, FL 34119","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"0CCA","name":"Creciente Condominium Association, Inc.","address":"7150 Estero Blvd Fort Myers, FL 33931","manager":"","managerEmail":""},{"tag":"0CLR","name":"Crystal Lake Property Owners' Association Two, Inc.","address":"14960 Collier Boulevard Naples, FL 34119","manager":"Scott Schlick","managerEmail":"clmgr@seacrestsw.com"},{"tag":"0CREN","name":"Crystal Lake Rentals LLC","address":"14960 Collier Boulevard Naples, FL 34119","manager":"Scott Schlick","managerEmail":"clmgr@seacrestsw.com"},{"tag":"0CLS","name":"Crystal Lake Sales LLC","address":"14960 Collier Boulevard Naples, FL 34119","manager":"Scott Schlick","managerEmail":"clmgr@seacrestsw.com"},{"tag":"CYPI","name":"Cypress Island Condominium Association, Inc.","address":"25000-25061 Cypress Hollow Ct. Bonita Springs, FL 34134","manager":"John Albright","managerEmail":"jalbright@seacrestsw.com"},{"tag":"CLC","name":"Cypress Lake Center Association, Inc.","address":"13720 Cypress Terrace Cir Ft Myers, FL 33907","manager":"Jeff Basik","managerEmail":"jpbafa@aol.com"},{"tag":"0DEER","name":"Deer Crossing Condominium Association, Inc.","address":"3910-3995 Deer Crossing Court Naples, FL 34114","manager":"Carolyn Sabin","managerEmail":"csabin@swpropmgt.com"},{"tag":"EGC","name":"Emerald Greens Condominium Association, Inc.","address":"316-940 Woodshire Lane Naples, FL 34105","manager":"John Albright","managerEmail":"jalbright@seacrestsw.com"},{"tag":"0ESM","name":"Esmeralda on Eighth Condominium Association, Inc.","address":"969-985 8th Avenue South Naples, FL 34102","manager":"Janine Curto","managerEmail":"jcurto@swpropmgt.com"},{"tag":"FGI","name":"Fairway Gardens Inc.","address":"190 Pebble Beach Blvd. Naples, FL 34113","manager":"Dierdre Woods","managerEmail":"dwoods@swpropmgt.com"},{"tag":"0FRP","name":"Forest Park Master Property Owners' Association, Inc.","address":"4060 Recreation Lane Naples, FL 34116","manager":"Luke Brooks","managerEmail":"lbrooks@seacrestsw.com"},{"tag":"GEO","name":"Georgetown Of Pelican Bay Property Owners Association, Inc.","address":"701 Nathan Hale Drive Naples, FL 34108","manager":"John Albright","managerEmail":"jalbright@seacrestsw.com"},{"tag":"GG2","name":"Glenmoor Greens II, Inc.","address":"880-994 Eastham/Hingham Way Naples, FL 34104","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"0GHWK","name":"Greyhawk at Golf Club of the Everglades Homeowners Association, Inc.","address":"9275 Horned Lark Drive Naples, FL 34120","manager":"Brett Beaver","managerEmail":"generalmanager@greyhawkhoa.com"},{"tag":"0GBN","name":"Gulf Bay Inc. of Naples","address":"2800 Gulf Shore Boulevard N Naples, FL 34103","manager":"Luke Brooks","managerEmail":"lbrooks@seacrestsw.com"},{"tag":"0GBV","name":"Gulf Breeze At Vanderbilt Condominium Assoc., Inc.","address":"21-25 Bluebill Avenue Naples, FL 34108","manager":"Yanary Anderson","managerEmail":"gbmanager@swpropmgt.com"},{"tag":"0GWE","name":"Gulf Winds East Condominium Association, Inc.","address":"1000-1024 Manatee Rd. Naples, FL 34114","manager":"Alena Gray","managerEmail":"Agray@seacrest-sw.com"},{"tag":"0HPP","name":"Hyde Park at Pelican Bay Condominium Association, Inc","address":"6320 Pelican Bay Blvd. Naples, FL 34108","manager":"Elizabeth Benfenati","managerEmail":"hydeparknaples@gmail.com"},{"tag":"IDS","name":"Interlachen Development Services Assoc., Inc.","address":"6770 Pelican Bay Blvd Naples, FL 34018","manager":"Tina Miller","managerEmail":"interlachen@swpropmgt.com"},{"tag":"IOC","name":"Interlachen On The Course, Inc.","address":"6820 Pelican Bay Blvd Naples, FL 34018","manager":"Tina Miller","managerEmail":"interlachen@swpropmgt.com"},{"tag":"IOG","name":"Interlachen On The Green Association, Inc.","address":"6760 Pelican Bay Blvd Naples, FL 34018","manager":"Tina Miller","managerEmail":"interlachen@swpropmgt.com"},{"tag":"IOGII","name":"Interlachen On The Green Two Assoc., Inc.","address":"6770 Pelican Bay Blvd Naples, FL 34018","manager":"Tina Miller","managerEmail":"interlachen@swpropmgt.com"},{"tag":"0IOA","name":"Interlachen One Association, Inc.","address":"6710 Pelican Bay Blvd Naples, FL 34108","manager":"Tina Miller","managerEmail":"interlachen@swpropmgt.com"},{"tag":"0ISQ","name":"Ironstone at The Quarry Condominium Association, Inc.","address":"9504-9558 Ironstone Terrace Naples, FL 34120","manager":"Carolyn Sabin","managerEmail":"csabin@swpropmgt.com"},{"tag":"JBM","name":"Jasmine Bay Master Association, Inc.","address":"4761 West Bay Blvd. Estero, FL 33928","manager":"Will Rego","managerEmail":"jbmanager@swpropmgt.com"},{"tag":"JBN","name":"Jasmine Bay North Condominium Association, Inc","address":"4761 West Bay Blvd Estero, FL 33928","manager":"Will Rego","managerEmail":"jbmanager@swpropmgt.com"},{"tag":"JBS","name":"Jasmine Bay South Condominium Association, Inc","address":"4751 West Bay Blvd. Estero, FL 33928","manager":"Will Rego","managerEmail":"jbmanager@swpropmgt.com"},{"tag":"JEN","name":"Jennifer Shores, Inc.","address":"2850 Gulf Shore Blvd N Naples, FL 34103","manager":"Luke Brooks","managerEmail":"lbrooks@seacrestsw.com"},{"tag":"0A6","name":"King's Lake Homeowners Association, Inc.","address":"2170 Buckingham Lane Naples, FL 34112","manager":"Janine Curto","managerEmail":"jcurto@swpropmgt.com"},{"tag":"LAG","name":"Lagomar Village Association, Inc","address":"8156 Fiddlers Creek Parkway Naples, FL 34114","manager":"Linda Marcos","managerEmail":"lmarcos@swpropmgt.com"},{"tag":"0LVC","name":"Laguna at Veneta Condominium Association, Inc.","address":"9300 Belle Court Naples, FL 34114","manager":"Linda Marcos","managerEmail":"lmarcos@swpropmgt.com"},{"tag":"LVP","name":"Lakeview Pines, Inc.","address":"4760-4798 West Blvd Naples, FL 34103","manager":"Janine Curto","managerEmail":"jcurto@swpropmgt.com"},{"tag":"0LAU","name":"Laurel Oaks at Pelican Bay Condominium, Inc.","address":"818-886 Tanbark Drive Naples, FL 34108","manager":"Tom Hansen","managerEmail":"thansen@seacrestsw.com"},{"tag":"LED","name":"Le Dauphin Condominium Association, Inc.","address":"9811 Gulf Shore Dr Naples, FL 34108","manager":"Carolyn Sabin","managerEmail":"csabin@swpropmgt.com"},{"tag":"BFBD","name":"Lely Barefoot Beach Dock Association","address":"Lely Barefoot Beach Dock 1-43 Bonita Springs, FL 34134","manager":"Karen Shepard","managerEmail":"office@barefootbeachpoa.org"},{"tag":"MLV","name":"Mallard\u2019s Landing Village Association, Inc.","address":"8402-8548 Mallards Way/Point Naples, FL 34114","manager":"Linda Marcos","managerEmail":"lmarcos@swpropmgt.com"},{"tag":"0MNA","name":"Mansions North At Artesia Naples Condominium Association, Inc.","address":"1359 Artesia Dr Naples, FL 34113","manager":"Emily Brooks","managerEmail":"artesiamgr@swpropmgt.com"},{"tag":"0MPL","name":"Maple Lane Estates Homeowner Association, Inc.","address":"5164-5191 Sugarwood Drive Naples, FL 34113","manager":"Michael Powell","managerEmail":"mpowell@seacrestsw.com"},{"tag":"0MAC","name":"Marbella Lakes Condominium Association, Inc.","address":"6664 Marbella Lane Naples, FL 34105","manager":"Nora Schweihs","managerEmail":"mlmanager@swpropmgt.com"},{"tag":"0MAR","name":"Marbella Lakes Owners Association, Inc.","address":"6664 Marbella Lane Naples, FL 34105","manager":"Nora Schweihs","managerEmail":"mlmanager@swpropmgt.com"},{"tag":"0MCV","name":"Mariner's Cove Condominium Association, Inc.","address":"305 Goodlette Road S Naples, FL 34102","manager":"Carolyn Sabin","managerEmail":"csabin@swpropmgt.com"},{"tag":"0MPW","name":"Mariposa at Whippoorwill Condominium Association, Inc.","address":"1305-1465 Mariposa Circle Naples, FL 34105","manager":"James Callahan","managerEmail":"jcallahan@seacrestsw.com"},{"tag":"0MEAD","name":"Meadowood of Naples Homeowners Association, Inc.","address":"14910 Wildflower Circle Naples, FL 34119","manager":"Chris Conti","managerEmail":"Meadowoodmgr@seacrestsw.com"},{"tag":"0MCA","name":"Menaggio Condominium Association, Inc.","address":"9270-9317 Menaggio Court Naples, FL 34114","manager":"Linda Marcos","managerEmail":"lmarcos@swpropmgt.com"},{"tag":"MTR","name":"Montara at Bonita Bay Association, Inc.","address":"3237-3380 Montara Dr Bonita Springs, FL 34134","manager":"John Albright","managerEmail":"jalbright@seacrestsw.com"},{"tag":"MGC","name":"Mystic Greens Commons Association, Inc.","address":"8485 Mystic Greens Way Naples, FL 34113","manager":"Ricardy Joseph","managerEmail":"rjoseph@seacrestsw.com"},{"tag":"MG1","name":"Mystic Greens I Condominium Association, Inc.","address":"8500-8560 Mystic Greens Way Naples, FL 34113","manager":"Ricardy Joseph","managerEmail":"rjoseph@seacrestsw.com"},{"tag":"MG2","name":"Mystic Greens II Condominium Association, Inc.","address":"8580-8600 Mystic Greens Way Naples, FL 34113","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"MG3","name":"Mystic Greens III Condominium Association, Inc.","address":"8300-8480 Mystic Greens Way Naples, FL 34113","manager":"Ricardy Joseph","managerEmail":"rjoseph@seacrestsw.com"},{"tag":"NBC","name":"Naples Big Cypress Property Owners Association, Inc.","address":"200-400 Basik Drive Naples, FL 34103","manager":"Keith Basik","managerEmail":"keith.basik@gmail.com"},{"tag":"0NCM","name":"Naples Casamore Association, Inc. / Naples Casemore Marina Assoc.","address":"1720-1764 Gulf Shore Blvd N Naples, FL 34102","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"NSBC","name":"Naples Sandpiper Bay Club, Inc.","address":"3001-3072 Sandpiper Bay Circle Naples, FL 34112","manager":"Sondra Vazquez","managerEmail":"rpmgrcondo@swpropmgt.com"},{"tag":"NBF","name":"Natura at Bonita Fairways Homeowners Association, Inc.","address":"9751 West Terry Street Bonita Springs, FL 34135","manager":"Michael Powell","managerEmail":"mpowell@seacrestsw.com"},{"tag":"NBC-Hideout","name":"NBC Hideout Condominium Association, Inc.","address":"173 Basik Drive Naples, FL 34114","manager":"Keith Basik","managerEmail":"keith.basik@gmail.com"},{"tag":"NSY","name":"North Star Yacht Club Condominium Association, Inc.","address":"3420 Hancock Bridge Parkway North Fort Myers, FL 33903","manager":"Eric Davenport","managerEmail":"nsycmgr@swpropmgt.com"},{"tag":"0OSP","name":"Osprey Pointe at Pelican Marsh Condominium Association, Inc.","address":"9005-9069 Whimbrel Watch Lane Naples, FL 34109","manager":"Ricardy Joseph","managerEmail":"rjoseph@seacrestsw.com"},{"tag":"0PAC","name":"Palermo at the Colony Condominium Association, Inc","address":"4875 Pelican Colony Boulevard Bonita Springs, FL 34134","manager":"Anthony Martinez","managerEmail":"Palermopm@seacrestsw.com"},{"tag":"0PSR","name":"Park Shore Resort Condominium Association, Inc.","address":"600 Neapolitan Way Naples, FL 34103","manager":"Kelly Cerino","managerEmail":"kcerino@swpropmgt.com"},{"tag":"PRN","name":"Pelican Ridge of Naples Association, Inc.","address":"780-879 Meadowland Drive Naples, FL 34108","manager":"Jamie Must","managerEmail":"jmust@seacrestsw.com"},{"tag":"0PMP","name":"Portico Master Property Owners' Association, Inc.","address":"14070 Portico Blvd Fort Myers, FL 33905","manager":"Alondra Villanueva","managerEmail":"PorticoMgr@Seacrestsw.com"},{"tag":"PP3","name":"Princeton Place At Wiggins Bay Condominium Three Association, Inc.","address":"340 Horsecreek Dr Naples, FL 34110","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"0PRF","name":"Promenade at the Forum Homeowners Association, Inc.","address":"3027 Via San Marco Ct. Fort Myers, FL 33905","manager":"James Callahan","managerEmail":"jcallahan@seacrestsw.com"},{"tag":"QH","name":"Quail Hollow Property Owners Association, Inc.","address":"6001 Hollow Drive Naples, FL 34112","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"RRW","name":"Radio Road Executive Warehouse Condominium Association, Inc.","address":"4776 Radio Road Naples, FL 34104","manager":"Tom Hansen","managerEmail":"thansen@seacrestsw.com"},{"tag":"0RFI","name":"Reflection Isles Master Association Inc.","address":"11375 Reflection Isles Blvd Fort Myers, FL 33912","manager":"Crystal McClary","managerEmail":"RIManager@seacrestsw.com"},{"tag":"0ROY","name":"Royal Pelican Association, Inc.","address":"4511-4591 Bay Beach Lane Fort Myers Beach, FL 33931","manager":"Michael Powell","managerEmail":"mpowell@seacrestsw.com"},{"tag":"0RPB","name":"Royal Pelican Boating Association, Inc.","address":"4511-4591 Bay Beach Lane Fortt Myers Beach, FL 33932","manager":"Michael Powell","managerEmail":"mpowell@seacrestsw.com"},{"tag":"0SBG","name":"Sabal Glen Homeowners Association, Inc.","address":"c/o Seacrest Southwest 1044 Castello Dr STE 206 Naples, FL 34103","manager":"James Callahan","managerEmail":"jcallahan@seacrestsw.com"},{"tag":"0SAV","name":"Savoy Owners Association Inc.","address":"4041 Gulf Shore Blvd N Naples, FL 34103","manager":"Daniel Isakov","managerEmail":"manager@savoynaples.com"},{"tag":"0STB","name":"Serafina At Tiburon Homeowners' Association, Inc.","address":"2880-2919 Tiburon Boulevard East Naples, FL 34109","manager":"Janine Curto","managerEmail":"jcurto@swpropmgt.com"},{"tag":"0SFC","name":"Serena at Fiddler's Creek Condominium Association, Inc.","address":"3160-3207 Serenity Court Naples, FL 34114","manager":"Carolyn Sabin","managerEmail":"csabin@swpropmgt.com"},{"tag":"0SCN","name":"Southern Clipper of Naples, Inc.","address":"3333 Gulf Shore Blvd North Naples, FL 34103","manager":"Nick Masino","managerEmail":"nmasino@swpropmgt.com"},{"tag":"SPW","name":"Spanish Wells Unit One Homeowners' Association, Inc.","address":"9821 Treasure Cay Lane Bonita Springs, FL 34135","manager":"Carolyn Sabin","managerEmail":"csabin@swpropmgt.com"},{"tag":"0IF","name":"Spinnaker Pointe At Windstar Condominium Association, Inc.","address":"3520-3588 Windjammer Circle Naples, FL 34112","manager":"Carolyn Sabin","managerEmail":"csabin@swpropmgt.com"},{"tag":"0STH","name":"Stonehill Manor Homeowners Association, Inc.","address":"17393 Stonehill Manor Drive North Fort Myers, FL 33917","manager":"James Callahan","managerEmail":"jcallahan@seacrestsw.com"},{"tag":"0SHM","name":"Sunset House of Marco Island, Inc.","address":"220 Seaview Court Marco Island, FL 34145","manager":"Dierdre Woods","managerEmail":"dwoods@swpropmgt.com"},{"tag":"0ABV","name":"The Abbey Management Association, Inc.","address":"1203-1232 Commonwealth Circle Naples, FL 34116","manager":"Alena Gray","managerEmail":"agray@swpropmgt.com"},{"tag":"BWC","name":"The Breakwater Commons Association, Inc.","address":"Breakwater Circle Naples, FL 34108","manager":"Lee Dixon","managerEmail":"Breakwatermanager@swpropmgt.com"},{"tag":"BWC1","name":"The Breakwater Condo I","address":"710-743 Bentwater Circle Naples, FL 34108","manager":"Lee Dixon","managerEmail":"Breakwatermanager@swpropmgt.com"},{"tag":"BWC2","name":"The Breakwater Condo II","address":"750-780 Bentwater Circle Naples, FL 34108","manager":"Lee Dixon","managerEmail":"Breakwatermanager@swpropmgt.com"},{"tag":"BWC3","name":"The Breakwater Condo III","address":"795-805 Bentwater Circle Naples, FL 34108","manager":"Lee Dixon","managerEmail":"Breakwatermanager@swpropmgt.com"},{"tag":"BWC4","name":"The Breakwater Condo IV","address":"815-840 Bentwater Circle Naples, FL 34108","manager":"Lee Dixon","managerEmail":"Breakwatermanager@swpropmgt.com"},{"tag":"BWC5","name":"The Breakwater Condo V","address":"Bentwater Circle & Sailaway Lane Naples, FL 34108","manager":"Lee Dixon","managerEmail":"Breakwatermanager@swpropmgt.com"},{"tag":"0CON","name":"The Cloisters of Naples, Inc.","address":"2701 Gulf Shore Blvd N Naples, FL 34103","manager":"Colby Williams","managerEmail":"pmcloisters@swpropmgt.com"},{"tag":"STG","name":"The Community Association For Stonegate, Collier County, Inc.","address":"6602-7385 Stonegate Drive Naples, FL 34109","manager":"James Callahan","managerEmail":"jcallahan@seacrestsw.com"},{"tag":"0FEG","name":"The Fairways At Emerald Greens Condominium Association, Inc.","address":"992 Woodshire Lane Naples, FL 34105","manager":"Michael Powell","managerEmail":"mpowell@seacrestsw.com"},{"tag":"0TMC","name":"The Madrid Club Inc.","address":"3430 Gulf Shore Blvd N Naples, FL 34103","manager":"John Zizzo","managerEmail":"jzizzo@seacrestsw.com"},{"tag":"0TMM","name":"The Mariner of Marco Island, Inc.","address":"44 Greenbrier St Marco Island 34145 Marco Island, FL 34145","manager":"Nancy Bolla","managerEmail":"pmmarinerofmarco@swpropmgt.com"},{"tag":"0875","name":"The Residences at 875 6th Avenue South Condominium Association, Inc.","address":"875 6th Avenue South Naples, FL 34102","manager":"Janine Curto","managerEmail":"jcurto@swpropmgt.com"},{"tag":"0SIR","name":"The Sanctuary at Imperial River Condominium Association, Inc.","address":"8675 River Homes Lane Bonita Springs, FL 34135","manager":"Trey Fields","managerEmail":"sanctuarymanager@swpropmgt.com"},{"tag":"STR","name":"The Strand Homeowner's Association, Inc.","address":"5840 Strand Blvd Naples, FL 34110","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"0SSC","name":"The Surfside Club Of Naples, Inc.","address":"1065 Gulf Shore Blvd. Naples, FL 34102","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"OIM","name":"Tra-Vigne' Condominium Association, Inc.","address":"170 Vineyards Blvd Naples, FL 34119","manager":"Sandy Hagedorn","managerEmail":"shagedorn@seacrestsw.com"},{"tag":"0TSV","name":"Tuscany at The Vineyards Condominium Association, Inc.","address":"100-110 Sienna Way Naples, FL 34119","manager":"Luke Brooks","managerEmail":"lbrooks@seacrestsw.com"},{"tag":"0TCM","name":"Tuscany Cove Master Property Owners' Association, Inc.","address":"15076 Toscana Way Naples, FL 34120","manager":"Laura Patel","managerEmail":"tcmanager@seacrestsw.com"},{"tag":"0VBB","name":"Vanderbilt Bay Condominium Association, Inc.","address":"10420 & 10482 Gulf Shore Dr Naples, FL 34108","manager":"Susan Hilton","managerEmail":"VBCManager@seacrestsw.com"},{"tag":"VSH","name":"Vanderbilt Shores Condominium Association, Inc.","address":"10701 Gulf Shore Drive Naples, FL 34108","manager":"Ron Mikolinski","managerEmail":"vbs@swpropmgt.com"},{"tag":"0VSC","name":"Vanderbilt Surf Colony Condominium, Phase I, Association, Inc.","address":"11 Bluebill Avenue Naples, FL 34108","manager":"Vinvent Vivo","managerEmail":"vsc1manager@seacrestsw.com"},{"tag":"0VBT1","name":"Vanderbilt Towers, Unit #1 of Naples, Inc.","address":"1 Bluebill Avenue Naples, FL 34108","manager":"Katelyn Kubasik","managerEmail":"vtmanager@seacrest-sw.com"},{"tag":"VBNY","name":"Venetian Bay North Yacht Club Condominium Association, Inc.","address":"4450-4680 Gulf Shore Blvd N Naples, FL 34103","manager":"John Zizzo","managerEmail":"jzizzo@seacrestsw.com"},{"tag":"0VEN","name":"Ventura At Pelican Marsh Homeowners' Association, Inc.","address":"8760-8933 Ventura Drive/Way Naples, FL 34109","manager":"Ricardy Joseph","managerEmail":"rjoseph@seacrestsw.com"},{"tag":"VDR","name":"Victor Del Rey Condominium Association, Inc.","address":"705 10th Street South Naples, FL 34102","manager":"Janine Curto","managerEmail":"jcurto@swpropmgt.com"},{"tag":"0VEC","name":"Villa Ensenada Condominium Association, Inc.","address":"1100 Clam Court Naples, FL 34102","manager":"Michael Powell","managerEmail":"mpowell@seacrestsw.com"},{"tag":"0VMH","name":"Villa Mare Homeowners Association, Inc.","address":"4700-4737 Villa Mare Lane Naples, FL 34103","manager":"","managerEmail":""},{"tag":"0VHA","name":"Village Homes At Artesia Naples Condominium Association, Inc.","address":"1460 Santiago Circle Naples, FL 34113","manager":"Dierdre Woods","managerEmail":"dwoods@swpropmgt.com"},{"tag":"0VBC","name":"Vintage Bay Condominium Association, Inc.","address":"133-337 Vintage Bay Drive Marco Island, FL 34145","manager":"Yahima Toledo","managerEmail":"vbmanager@swpropmgt.com"},{"tag":"0VHBC","name":"Vista at Heritage Bay Commons Association, Inc.","address":"9047-9101 Gervais Circle Naples, FL 34120","manager":"Tom Hansen","managerEmail":"thansen@seacrestsw.com"},{"tag":"0V1HB","name":"Vista I at Heritage Bay Condominium Association, Inc.","address":"9064-9073 Gervais Circle Naples, FL 34120","manager":"Tom Hansen","managerEmail":"thansen@seacrestsw.com"},{"tag":"0V3HB","name":"Vista III at Heritage Bay Condominium Association, Inc.","address":"9047-9063 Gervais Circle Naples, FL 34120","manager":"Tom Hansen","managerEmail":"thansen@seacrestsw.com"},{"tag":"0VTHB","name":"Vista Townhomes at Heritage Bay Association, Inc.","address":"9072-9101 Gervais Circle Naples, FL 34120","manager":"Tom Hansen","managerEmail":"thansen@seacrestsw.com"},{"tag":"0WWS","name":"Wedge Wood at The Strand Condominium Association, Inc.","address":"5968 Wedge Wood Lane Naples, FL 34110","manager":"Jamie Must","managerEmail":"jmust@seacrestsw.com"},{"tag":"WTC","name":"Whisper Trace Condominium Association, Inc","address":"Whisper Trace Way Naples, FL 34114","manager":"Linda Marcos","managerEmail":"lmarcos@swpropmgt.com"},{"tag":"WC1","name":"Winding Cypress Homeowners Association, Inc.","address":"7180 Winding Cypress Dr. Naples, FL 34114","manager":"Stephen Dorozensk","managerEmail":"wcmanager@swpropmgt.com"}]
    for a in assocs:
        c.execute("""INSERT INTO associations (tag,name,address,manager,manager_email,updated_at)
                     VALUES (%s,%s,%s,%s,%s,%s)
                     ON CONFLICT (tag) DO NOTHING""",
                  (a["tag"],a["name"],a.get("address",""),a.get("manager",""),a.get("managerEmail",""),datetime.utcnow().isoformat()))

# ── Gmail SMTP ──────────────────────────────────────────────────────────────

def send_email_gmail(to_email, cc_emails, subject, body_text):
    if not GMAIL_USER or not GMAIL_PASS:
        raise RuntimeError("Email is not configured on the server (missing GMAIL_USER / GMAIL_APP_PASSWORD)")
    msg = MIMEMultipart()
    msg["From"]     = f"Seacrest Southwest <{GMAIL_USER}>"
    msg["To"]       = to_email
    msg["Subject"]  = subject
    msg["Reply-To"] = REPLY_TO
    if cc_emails:
        msg["Cc"] = ", ".join(e for e in cc_emails if e)
    msg.attach(MIMEText(body_text, "plain"))
    all_recipients = [to_email] + [e for e in cc_emails if e]
    # timeout=10 so a blocked/stalled connection fails fast with a real error
    # instead of hanging until the gunicorn worker is killed (which surfaced
    # to users as an endless "Sending..." spinner followed by a bare 503).
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
        server.login(GMAIL_USER, GMAIL_PASS)
        server.sendmail(GMAIL_USER, all_recipients, msg.as_string())

# ── Email building ──────────────────────────────────────────────────────────

def parse_exp_date(d):
    """Parse an expiration date that may come in as strict ISO (YYYY-MM-DD,
    what the vendor edit form's <input type=date> always produces) OR as a
    US-style MM/DD/YYYY or M/D/YYYY string (what the CSV importer sends
    verbatim from the spreadsheet, unconverted). Returns a date or None."""
    if not d: return None
    from datetime import date
    import re
    d = str(d).strip()
    try:
        return date.fromisoformat(d)
    except ValueError:
        pass
    m = re.match(r'^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$', d)
    if m:
        month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            return date(year, month, day)
        except ValueError:
            return None
    return None

def date_status(d):
    from datetime import date
    exp = parse_exp_date(d)
    if exp is None: return "missing"
    delta = (exp - date.today()).days
    if delta < 0: return "expired"
    if delta <= 30: return "expiring"
    return "ok"

def normalize_vendor(v):
    v["gl_type"] = (v.get("gl_type") or "coi").strip().lower()
    v["wc_type"] = (v.get("wc_type") or "coi").strip().lower()
    v["bl_type"] = (v.get("bl_type") or "license").strip().lower()
    return v

def build_needed_list(v, assocs_map):
    needed = []
    s = date_status(v.get("gl_exp","")) if v.get("gl_type","coi") != "none" else "ok"
    if s != "ok": needed.append("General Liability COI" if s=="missing" else f"GL COI ({s})")
    wc_type = v.get("wc_type","coi")
    if wc_type != "none":
        s2 = date_status(v.get("wc_exp",""))
        label = "Workers' Comp COI or Workers' Comp Exemption"
        if s2 != "ok": needed.append(label if s2=="missing" else f"{label} ({s2})")
    bl_type = v.get("bl_type","license")
    if bl_type != "none":
        s3 = date_status(v.get("bl_exp",""))
        label = "Business License or Business Tax Receipt"
        if s3 != "ok": needed.append(label if s3=="missing" else f"{label} ({s3})")
    if not v.get("w9"): needed.append("W9")
    return needed

def build_email_body(v, assocs_map, needed):
    tags = [t.strip().upper() for t in (v.get("tags") or "").split(",") if t.strip()]
    sender = v.get("sender") or "Sandra"
    cois_on_file = v.get("cois_on_file") or {}
    if isinstance(cois_on_file, str):
        try:
            cois_on_file = json.loads(cois_on_file) or {}
        except (ValueError, TypeError):
            cois_on_file = {}
    body = f"Dear {v['name']} Team,\n\nThank you for your interest in becoming an approved vendor. To complete your setup and get you added to our vendor list, we need the following documents on file:\n\n"
    for i, item in enumerate(needed, 1):
        body += f"{i}. {item}\n"
    # These "must list each association" instructions only make sense when
    # we're actually still asking the vendor to (re)send that COI. Gating
    # only on whether the vendor has association tags — as this used to do —
    # meant a vendor with a current, on-file GL/WC COI still got told to
    # send one, which reads as "still asking for it" even though it had
    # already been dropped from the numbered list above.
    #
    # Within that, an association whose per-association GL/WC box has
    # already been checked off (cois_on_file) doesn't need to be asked
    # for again either — otherwise an association marked as on file still
    # showed up in this list every time the vendor's overall COI was
    # outstanding for a different association.
    # cois_on_file is keyed by association tag; be tolerant of tag/flag
    # casing since it's populated by the frontend, not this API.
    cois_on_file_ci = {(k or "").strip().upper(): (val or {}) for k, val in cois_on_file.items()}

    def _coi_flag(tag, flag):
        entry = cois_on_file_ci.get(tag, {})
        if not isinstance(entry, dict):
            return bool(entry)
        return bool(entry.get(flag) or entry.get(flag.upper()) or entry.get(flag.lower()))

    gl_outstanding = v.get("gl_type","coi") != "none" and date_status(v.get("gl_exp","")) != "ok"
    wc_outstanding = v.get("wc_type","coi") == "coi" and date_status(v.get("wc_exp","")) != "ok"
    gl_tags = [t for t in tags if not _coi_flag(t, "gl")]
    wc_tags = [t for t in tags if not _coi_flag(t, "wc")]
    if gl_tags and gl_outstanding:
        body += "\nYour General Liability COI must list each of the following as an Additional Insured / Certificate Holder — please provide a separate COI (or endorsement) for each association:\n\n"
        for i, tag in enumerate(gl_tags, 1):
            a = assocs_map.get(tag)
            body += f"{i}. "
            if a:
                body += a["name"]
                if a.get("address"): body += f"\n   {a['address']}"
            else: body += tag
            body += "\n\n"
    if wc_tags and wc_outstanding:
        body += "Your Workers' Comp COI must also list each of the following as Certificate Holder:\n\n"
        for i, tag in enumerate(wc_tags, 1):
            a = assocs_map.get(tag)
            body += f"{i}. "
            if a:
                body += a["name"]
                if a.get("address"): body += f"\n   {a['address']}"
            else: body += tag
            body += "\n\n"
    body += f"Please reply to this email with all required documents attached. Once everything is received and verified, we will finalize your vendor account and you will be ready to receive work orders.\n\nIf you have any questions, please don't hesitate to reach out.\n\nThank you,\n{sender}"
    return body

def get_cc_list(v, assocs_map):
    tags = [t.strip().upper() for t in (v.get("tags") or "").split(",") if t.strip()]
    seen = set(); ccs = []
    for tag in tags:
        a = assocs_map.get(tag)
        if a and a.get("manager_email") and a["manager_email"].lower() not in seen:
            seen.add(a["manager_email"].lower())
            ccs.append({"name": a.get("manager",""), "email": a["manager_email"]})
    return ccs

# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/api/associations/sync", methods=["POST"])
@require_auth
def sync_associations():
    data = request.json
    incoming = data.get("associations", [])
    if not incoming:
        return jsonify({"error": "No associations provided"}), 400
    now = datetime.utcnow().isoformat()
    incoming_tags = {a["tag"].upper() for a in incoming if a.get("tag")}
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT tag FROM associations")
    existing_tags = {r["tag"].upper() for r in c.fetchall()}
    added = updated = removed = 0
    for a in incoming:
        tag = (a.get("tag") or "").strip().upper()
        if not tag: continue
        name=a.get("name","").strip(); manager=a.get("manager","").strip()
        manager_email=a.get("manager_email","").strip(); address=a.get("address","").strip()
        if tag in existing_tags:
            c.execute("UPDATE associations SET name=%s,manager=%s,manager_email=%s,address=%s,updated_at=%s WHERE tag=%s",
                      (name,manager,manager_email,address,now,tag)); updated+=1
        else:
            c.execute("INSERT INTO associations (tag,name,address,manager,manager_email,updated_at) VALUES (%s,%s,%s,%s,%s,%s)",
                      (tag,name,address,manager,manager_email,now)); added+=1
    for tag in existing_tags:
        if tag not in incoming_tags:
            c.execute("DELETE FROM associations WHERE tag=%s",(tag,)); removed+=1
    conn.commit(); conn.close()
    return jsonify({"ok":True,"added":added,"updated":updated,"removed":removed})

@app.route("/api/associations", methods=["GET"])
@require_auth
def get_associations():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM associations ORDER BY tag")
    rows = c.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/associations/<tag>", methods=["PUT"])
@require_auth
def update_association(tag):
    data = request.json; now = datetime.utcnow().isoformat()
    conn = get_db(); c = conn.cursor()
    c.execute("""INSERT INTO associations (tag,name,address,manager,manager_email,updated_at)
                 VALUES (%s,%s,%s,%s,%s,%s)
                 ON CONFLICT (tag) DO UPDATE SET
                 name=EXCLUDED.name, address=EXCLUDED.address,
                 manager=EXCLUDED.manager, manager_email=EXCLUDED.manager_email,
                 updated_at=EXCLUDED.updated_at""",
              (tag,data.get("name",""),data.get("address",""),data.get("manager",""),data.get("manager_email",""),now))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/associations/<tag>", methods=["DELETE"])
@require_auth
def delete_association(tag):
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM associations WHERE tag=%s",(tag,))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/vendors", methods=["GET"])
@require_auth
def get_vendors():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM vendors ORDER BY created_at ASC")
    vendors = c.fetchall()
    result = []
    for v in vendors:
        vd = dict(v)
        vd = normalize_vendor(vd)
        c.execute("SELECT * FROM email_log WHERE vendor_id=%s ORDER BY sent_at DESC",(v["id"],))
        vd["email_log"] = [dict(l) for l in c.fetchall()]
        result.append(vd)
    conn.close()
    return jsonify(result)

@app.route("/api/vendors", methods=["POST"])
@require_auth
def create_vendor():
    import uuid
    data = request.json; vid = str(uuid.uuid4()); now = datetime.utcnow().isoformat()
    conn = get_db(); c = conn.cursor()
    c.execute("""INSERT INTO vendors
        (id,name,email,sender,gl_exp,gl_type,wc_exp,wc_type,bl_exp,bl_type,w9,tags,notes,cois_on_file,created_at,updated_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (vid,data["name"],data.get("email",""),data.get("sender","Sandra"),
         data.get("gl_exp",""),(data.get("gl_type") or "coi").strip().lower(),
         data.get("wc_exp",""),(data.get("wc_type") or "coi").strip().lower(),
         data.get("bl_exp",""),(data.get("bl_type") or "license").strip().lower(),
         1 if data.get("w9") else 0,data.get("tags",""),data.get("notes",""),
         json.dumps(data.get("cois_on_file",{})),now,now))
    conn.commit(); conn.close()
    return jsonify({"id":vid,"ok":True})

@app.route("/api/vendors/import", methods=["POST"])
@require_auth
def import_vendors():
    import uuid
    data = request.json; vendors_in = data.get("vendors",[]); now = datetime.utcnow().isoformat()
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT tag FROM associations")
    known = {r["tag"] for r in c.fetchall()}

    # Match incoming rows against existing vendors so a re-upload of the same
    # master list UPDATES the vendor already on file (including its
    # expiration dates) instead of creating a duplicate row. Matched first by
    # email (most reliable), then falls back to an exact name match.
    c.execute("SELECT id, name, email, gl_type, wc_type, bl_type, w9 FROM vendors")
    existing_rows = [dict(r) for r in c.fetchall()]
    by_email = {r["email"].strip().lower(): r["id"] for r in existing_rows if r.get("email")}
    by_name  = {r["name"].strip().lower(): r["id"] for r in existing_rows if r.get("name")}

    added = updated = 0
    for v in vendors_in:
        if not v.get("name"): continue
        raw_tags = [t.strip().upper() for t in (v.get("tags","") or "").split(",") if t.strip()]
        filtered_tags = ", ".join(t for t in raw_tags if t in known)
        email_key = (v.get("email") or "").strip().lower()
        name_key  = v["name"].strip().lower()
        match_id = by_email.get(email_key) if email_key else None
        if not match_id:
            match_id = by_name.get(name_key)

        if match_id:
            # The CSV mapper always sends gl_type/wc_type/bl_type/w9 with a
            # default value (coi/license/false) even when the user left that
            # column unmapped, so a plain overwrite here would silently wipe
            # out a "Not Required" flag or a confirmed W9 that was set by
            # hand in the vendor edit form on every re-upload of the sheet.
            # Preserve whatever is already on file for those four fields on
            # an update; the CSV only drives identity, dates, and tags.
            c.execute("""UPDATE vendors SET
                name=%s,email=%s,sender=%s,gl_exp=%s,wc_exp=%s,
                bl_exp=%s,tags=%s,updated_at=%s
                WHERE id=%s""",
                (v["name"],v.get("email",""),v.get("sender","Sandra"),
                 v.get("gl_exp",""),v.get("wc_exp",""),
                 v.get("bl_exp",""),filtered_tags,now,match_id))
            updated += 1
        else:
            gl_type = (v.get("gl_type") or "coi").strip().lower()
            wc_type = (v.get("wc_type") or "coi").strip().lower()
            bl_type = (v.get("bl_type") or "license").strip().lower()
            vid = str(uuid.uuid4())
            c.execute("""INSERT INTO vendors
                (id,name,email,sender,gl_exp,gl_type,wc_exp,wc_type,bl_exp,bl_type,w9,tags,notes,cois_on_file,created_at,updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (vid,v["name"],v.get("email",""),v.get("sender","Sandra"),
                 v.get("gl_exp",""),gl_type,v.get("wc_exp",""),wc_type,
                 v.get("bl_exp",""),bl_type,
                 1 if v.get("w9") else 0,filtered_tags,v.get("notes",""),"{}", now, now))
            # Newly-inserted vendors are matchable by later rows in the same
            # CSV too (e.g. duplicate rows for the same vendor).
            if email_key: by_email[email_key] = vid
            by_name[name_key] = vid
            added += 1
    conn.commit(); conn.close()
    return jsonify({"added":added,"updated":updated,"ok":True})

@app.route("/api/vendors/<vid>", methods=["PUT"])
@require_auth
def update_vendor(vid):
    data = request.json; now = datetime.utcnow().isoformat()
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT tag FROM associations")
    known = {r["tag"] for r in c.fetchall()}
    raw_tags = [t.strip().upper() for t in (data.get("tags","") or "").split(",") if t.strip()]
    filtered_tags = ", ".join(t for t in raw_tags if t in known)
    c.execute("""UPDATE vendors SET
        name=%s,email=%s,sender=%s,gl_exp=%s,gl_type=%s,wc_exp=%s,wc_type=%s,
        bl_exp=%s,bl_type=%s,w9=%s,tags=%s,notes=%s,cois_on_file=%s,updated_at=%s
        WHERE id=%s""",
        (data["name"],data.get("email",""),data.get("sender","Sandra"),
         data.get("gl_exp",""),(data.get("gl_type") or "coi").strip().lower(),
         data.get("wc_exp",""),(data.get("wc_type") or "coi").strip().lower(),
         data.get("bl_exp",""),(data.get("bl_type") or "license").strip().lower(),
         1 if data.get("w9") else 0,filtered_tags,data.get("notes",""),
         json.dumps(data.get("cois_on_file",{})),now,vid))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/vendors/<vid>", methods=["DELETE"])
@require_auth
def delete_vendor(vid):
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM email_log WHERE vendor_id=%s",(vid,))
    c.execute("DELETE FROM vendors WHERE id=%s",(vid,))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/vendors/<vid>/toggle", methods=["POST"])
@require_auth
def toggle_field(vid):
    field = request.json.get("field")
    if field not in ("w9",): return jsonify({"error":"Invalid field"}), 400
    conn = get_db(); c = conn.cursor()
    c.execute(f"SELECT {field} FROM vendors WHERE id=%s",(vid,))
    row = c.fetchone()
    if not row: conn.close(); return jsonify({"error":"Not found"}), 404
    new_val = 0 if row[field] else 1
    c.execute(f"UPDATE vendors SET {field}=%s, updated_at=%s WHERE id=%s",
              (new_val,datetime.utcnow().isoformat(),vid))
    conn.commit(); conn.close()
    return jsonify({"ok":True,"value":bool(new_val)})

@app.route("/api/vendors/<vid>/send-email", methods=["POST"])
@require_auth
def send_vendor_email(vid):
    import uuid
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM vendors WHERE id=%s",(vid,))
    v = c.fetchone()
    if not v: conn.close(); return jsonify({"error":"Vendor not found"}), 404
    v = dict(v)
    v = normalize_vendor(v)
    c.execute("SELECT * FROM associations")
    assocs = {r["tag"]:dict(r) for r in c.fetchall()}
    needed = build_needed_list(v, assocs)
    if not needed: conn.close(); return jsonify({"error":"No documents outstanding"}), 400
    if not v.get("email"): conn.close(); return jsonify({"error":"No vendor email on file"}), 400
    subject = f"New Vendor Setup — Required Documents for {v['name']}"
    body    = build_email_body(v, assocs, needed)
    ccs     = get_cc_list(v, assocs)
    cc_emails = [c2["email"] for c2 in ccs]
    try:
        send_email_gmail(v["email"], cc_emails, subject, body)
    except Exception as e:
        conn.close(); return jsonify({"error":str(e)}), 500
    log_id = str(uuid.uuid4())
    c.execute("""INSERT INTO email_log (id,vendor_id,vendor_name,vendor_email,sent_at,docs_requested,cc_list)
                 VALUES (%s,%s,%s,%s,%s,%s,%s)""",
              (log_id,vid,v["name"],v["email"],datetime.utcnow().isoformat(),
               json.dumps(needed),json.dumps(ccs)))
    conn.commit(); conn.close()
    return jsonify({"ok":True,"logged":True})

@app.route("/api/vendors/bulk-send-email", methods=["POST"])
@require_auth
def bulk_send_vendor_email():
    """Send the onboarding-documents email to several vendors in one request.

    Body: {"vendor_ids": ["id1","id2",...]}  (optional — omit/empty to target
    every vendor that currently has outstanding docs and an email on file).

    Each vendor is attempted independently so one bad address or one failed
    send doesn't block the rest of the batch; per-vendor results are returned
    so the caller can show exactly what succeeded and what needs attention.
    """
    import uuid
    vendor_ids = (request.json or {}).get("vendor_ids") or []
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM associations")
    assocs = {r["tag"]: dict(r) for r in c.fetchall()}

    if vendor_ids:
        c.execute("SELECT * FROM vendors WHERE id = ANY(%s)", (vendor_ids,))
        vendors = [dict(r) for r in c.fetchall()]
        found_ids = {v["id"] for v in vendors}
        missing = [vid for vid in vendor_ids if vid not in found_ids]
    else:
        c.execute("SELECT * FROM vendors")
        vendors = [dict(r) for r in c.fetchall()]
        missing = []

    results = [{"vendor_id": vid, "ok": False, "error": "Vendor not found"} for vid in missing]

    for v in vendors:
        vid = v["id"]
        v = normalize_vendor(v)
        needed = build_needed_list(v, assocs)
        if not needed:
            if vendor_ids:  # explicit target with nothing outstanding is worth reporting
                results.append({"vendor_id": vid, "vendor_name": v["name"], "ok": False,
                                 "error": "No documents outstanding"})
            continue
        if not v.get("email"):
            results.append({"vendor_id": vid, "vendor_name": v["name"], "ok": False,
                             "error": "No vendor email on file"})
            continue

        subject   = f"New Vendor Setup — Required Documents for {v['name']}"
        body      = build_email_body(v, assocs, needed)
        ccs       = get_cc_list(v, assocs)
        cc_emails = [c2["email"] for c2 in ccs]
        try:
            send_email_gmail(v["email"], cc_emails, subject, body)
        except Exception as e:
            results.append({"vendor_id": vid, "vendor_name": v["name"], "ok": False, "error": str(e)})
            continue

        log_id = str(uuid.uuid4())
        c.execute("""INSERT INTO email_log (id,vendor_id,vendor_name,vendor_email,sent_at,docs_requested,cc_list)
                     VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                  (log_id, vid, v["name"], v["email"], datetime.utcnow().isoformat(),
                   json.dumps(needed), json.dumps(ccs)))
        conn.commit()
        results.append({"vendor_id": vid, "vendor_name": v["name"], "ok": True})

    conn.close()
    sent = sum(1 for r in results if r["ok"])
    return jsonify({"ok": True, "sent": sent, "failed": len(results) - sent, "results": results})

@app.route("/api/preview-email/<vid>", methods=["GET"])
@require_auth
def preview_email(vid):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM vendors WHERE id=%s",(vid,))
    v = c.fetchone()
    if not v: conn.close(); return jsonify({"error":"Not found"}), 404
    v = dict(v)
    v = normalize_vendor(v)
    c.execute("SELECT * FROM associations")
    assocs = {r["tag"]:dict(r) for r in c.fetchall()}
    conn.close()
    needed = build_needed_list(v, assocs)
    body   = build_email_body(v, assocs, needed)
    ccs    = get_cc_list(v, assocs)
    return jsonify({"subject":f"New Vendor Setup — Required Documents for {v['name']}",
                    "to":v.get("email",""),"cc":ccs,"body":body,"needed":needed})

@app.route("/api/email-log", methods=["GET"])
@require_auth
def get_email_log():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM email_log ORDER BY sent_at DESC")
    rows = c.fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/")
def index():
    return jsonify({"status":"ok","service":"vendor-onboarding-api"})

@app.route("/health")
def health():
    return jsonify({"status":"ok"})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))

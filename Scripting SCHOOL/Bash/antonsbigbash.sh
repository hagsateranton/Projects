#!/bin/bash

# -- Konfiguration -- 
AUTH_LOG="/var/log/auth.log"
readonly AUTH_LOG

SYSLOG="/var/log/syslog"
readonly SYSLOG

REPORT_FILE="security_report_$(date +%Y%m%d).txt"
readonly REPORT_FILE

ACTIONS_LOG="/var/log/security_actions.log"
readonly ACTIONS_LOG

BACKUP_DIR="/backup/logs"
readonly BACKUP_DIR
# ------ READONLY används för att inte råka modifiera eller ta sönder något som inte ska redigera/modifieras på något sätt

# Tar bort rapporter äldre än 7 dagar om det finns men skickar ett meddelande om det inte finns något att ta bort eller leta efter
if ls security_report_*.txt 1> /dev/null 2>&1; then
    find "$(pwd)" -name "security_report_*.txt" -mtime +7 -exec rm {} \;
else
    echo "Ingen felaktig rapport hittades, nothing to delete buster"
fi

#ser till att blocked_ips.txt existerar
touch blocked_ips.txt

# - förbereder och skapar temp rapportfil
TMP_FILE=$(mktemp)
trap 'rm -f "$TMP_FILE"' EXIT #ser till att filen raderas om skriptet avbryts oväntat
touch "$REPORT_FILE" #skapar rapportfilen om den inte finns

# -- bestämmer tidsramen igenom att generera en string med tidsstämpel, i det här fallet senaste 24h
SINCE_DATE=$(date --date="24 hours ago" "+%b %e")

#kontrollerar om loggfilerna finns och är läsbara
if [[ ! -f "$AUTH_LOG" || ! -f "$SYSLOG" ]]; then
    echo "Loggfilerna hittades inte eller kan inte läsas!"
    exit 1
fi

# -- extraherar relevant information, lösenord, användare etc
grep -E "$SINCE_DATE" "$AUTH_LOG" "$SYSLOG" | grep -E "Failed password|Invalid user|Accepted password|session opened" > "$TMP_FILE"

# -- Analyserar loggar
declare -A IP_FAIL_COUNT # deklarerar en ny array för att räkna misslyckade ingloggningsförsök från ip addresser
declare -A IP_USER_MAP # deklarerar en ny array för att koppla ip-adresser till användarnamn

#Loggar starten av log analysen
echo "$(date): Starting log analysis... " >> "$ACTIONS_LOG" 

while read -r line; do # startar en loop som läser varje line i den filtrerade logdatan
    IP=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}') #extraherar IP addressen från line
    USER=$(echo "$line" | grep -oP '(?<=user )\w+') # extraherar användarnamnet med grep
    EVENT="" #initialiserar variablen för event

    if echo "$line" | grep -q "Failed password"; then #kollar om det finns ett failed password och tecknar det som ett event 
        EVENT="Failed password"
        (( IP_FAIL_COUNT["$IP"]++ ))  #ökar räknaren för misslyckade försök för ip addressen när det gäller lösenord

    elif echo "$line" | grep -q "Invalid user"; then #kollar om det finns en ogiltig användare och tecknar det i event variabeln
        EVENT="Invalid user"
        (( IP_FAIL_COUNT["$IP"]++ )) # ökar räknaren för misslyckade försök för ogiltiga användare

    elif echo "$line" | grep -q "Accepted password"; then #kollar om det finns ett accepterat lösenord och tecknar i event variabeln
        EVENT="Accepted password"

    elif echo "$line" | grep -q "session opened"; then #tecknar när en session öppnas och tecknar det i event variabeln
        EVENT="session opened"
    fi

    [[ -n "$IP" && -n "$EVENT" ]] && echo "$line" >> "$REPORT_FILE" #printar eventet i rapporten om det finns ett event och ip address
    [[ -n "$IP" && -n "$USER" ]] && IP_USER_MAP["$IP"]="$USER" #kopplar ip addressen till användarnnamnet i arrayen IP_USER_MAP
    [[ -n "$IP" && "$EVENT" == "Failed password" ]] && echo "$IP" >> blocked_ips.txt #skriver ip addressen till blocked_ips.txt om det är ett failed password event
    #------- NOTERA att blockerade ip addresserna kan leda till bekymmer om inte korrekt hanterad över tid då den kan ge utslag på false positives etc
done < "$TMP_FILE" # avslutar while loopen och läser från den temporära filen

#ser till att ufw är installerat
if ! command -v ufw &> /dev/null; then 
    echo "Error: ufw not installed."
    exit 1
fi

# -- noterar ip med hög risknivå
echo -e "\n--- High-Risk IPs (Over 20 Failed Attempts) ---" >> "$REPORT_FILE" #lägger till en sektion för riskabla ip addresser i rapporten
echo "----------------------------------------" >> "$REPORT_FILE" #skapar en separation i rapporten

for ip in "${!IP_FAIL_COUNT[@]}"; do #loopar igenom arrayen med ip addresser
    if [ "${IP_FAIL_COUNT[$ip]}" -gt 20 ]; then #kollar om antalet misslyckande försök är över 20
        echo "HIGH RISK: $ip - ${IP_FAIL_COUNT[$ip]} failed attempts (user: ${IP_USER_MAP[$ip]})" >> "$REPORT_FILE"  #loggar riskabla ip addresser till arrray
        
        #försöker blockera IP med ufw
        if ufw deny from "$ip" >> "$ACTIONS_LOG" 2>&1; then
            echo "$(date): Successfully blocked $ip due to excessive failed login attempts." >> "$ACTIONS_LOG" #loggar blockeringen i actions loggen
        else
            echo "$(date): Failed to block $ip using ufw. Check permissions or UFW config" >> "$ACTIONS_LOG" #loggar misslyckad blockering
        fi
    fi
done
#----- slut på loop -----

# -- backup loggar
mkdir -p "$BACKUP_DIR" #skapar backup directory med -p vilket gör parent directory om det behövs vilket skapar nödvändig pathing
tar -czf "$BACKUP_DIR/log_backup_$(date +%Y%m%d).tar.gz" "$AUTH_LOG" "$SYSLOG" 2>/dev/null #skapar nytt arkiv, compressar och specifierar namnet på arkivfilen

#  -- Raderar äldre loggar (äldre än 7 dagar)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -exec rm {} \;

# -- Rensning 
rm "$TMP_FILE"

# -- Feedback 
readonly FEEDBACK_FILE="feedback_summary.txt" # för att få direkt feedback när koden används
echo "Körningssammanfattning för $(date):" > "$FEEDBACK_FILE"
echo "Totalt blockerade IP-adresser: $(wc -l < blocked_ips.txt)" >> "$FEEDBACK_FILE"
echo "Rapport skapad: $REPORT_FILE" >> "$FEEDBACK_FILE"
echo "Arkivering klar i: $BACKUP_DIR" >> "$FEEDBACK_FILE"

#- Under construction
EMAIL="test@testmannen3000.com"  # exempel email ###OBSERVERA FUNKTION VAR INTE HELT TESTAD DÅ JAG GLÖMDE SÄTTA UPP EN SÄKER LOKAL EMAIL :P
LAST_EMAIL_FILE="/home/anton/last_email_sent.txt"
# -- skickar rapport till email om email plugin är aktiverat och funktionellt
if [[ ! -f "$LAST_EMAIL_FILE" || $(($(date +%s) - $(stat -c %Y "$LAST_EMAIL_FILE"))) -ge 43200 ]]; then
    mail -s "Daglig säkerhetsrapport - $(date +%Y-%m-%d)" "$EMAIL" < "$REPORT_FILE" # skickar rapporten som ett email (om aktiverat)
    touch "$LAST_EMAIL_FILE" # uppdaterar tidsstämpeln för senaste skickade email
fi

# ser till att email variablerna fungerar
if [[ -z "$EMAIL" || -z "$LAST_EMAIL_FILE" ]]; then
    echo "Error: Email config missing." >&2
    exit 1
fi

#Om mail funktionaliteten inte är installerad skickar den fel meddelande
if ! command -v mail &> /dev/null; then
    echo "Error: Mail functionality not installed."
    exit 1
fi
# -- skickar rapport till email om email plugin är aktiverat och funktionellt
mail -s "Daglig säkerhetsrapport - $(date +%Y-%m-%d)" "$EMAIL" < "$REPORT_FILE" #skickar rapporten som ett email (om aktiverat)

echo "Script executed successfully, check $FEEDBACK_FILE for details you silly goober!" #jag är väldigt trött
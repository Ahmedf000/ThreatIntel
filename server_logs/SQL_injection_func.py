import re
from urllib.parse import unquote
from colors.color import Colors



def SQLi_patterns(param):

    """going to hardcode multiple SQLi techniques"""



    _RE = re.compile(r".*?")

    KEYWORD_INJECTION = [
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
        "ALTER", "EXEC", "EXECUTE", "CAST(", "CONVERT(", "DECLARE",
        "TRUNCATE", "ORDER BY",
    ]

    KEYWORD_HEX_ENCODED = [
        "0x53454c454354", "0x494e534552545454", "0x55504441544545",
        "0x44454c455445", "0x44524f50", "0x435245415445", "0x414c544552",
        "0x45584543", "0x455845435554455", "0x434153542828",
        "0x434f4e5645525428", "0x4445434c415245", "0x5452554e43415445",
        "0x4f52444552", "0x6f72646572", "0x6f7264657220627",
    ]

    UNION_BASED_INJECTION = [
        "UNION SELECT", "UNION ALL SELECT",
        "UNION+SELECT", "UNION%20SELECT",
    ]

    BLIND_TIME_BASED_INJECTION = [
        "SLEEP(", "WAITFOR DELAY", "BENCHMARK(",
        "PG_SLEEP(", "DELAY '0:0:",
    ]

    BLIND_BOOLEAN_BASED_INJECTION = [
        "AND 1=1", "AND 1=2", "AND 1=0",
        "OR 1=1", "OR 1=2",
        "' AND '1'='1", "' AND '1'='2",
    ]

    ERROR_BASED_INJECTION = [
        "1'", "1\\.'", "-1'", "-1)'",
        "1'--/**/-", "/*!500001'--+-*/",
        "1'--/*--*/-", "1'--/*&a=*/-", "1'--/*1337*/-",
        "1'--/**_**/-", "1'--%0A-", "1'--%0b-",
        "1'--%0d%0A-", "1'--%23%0A-", "1'--%23foo%0D%0A-",
        "1'--%23foo*%2F*bar%0D%0A-", "1'--#qa%0A#%0A-",
        "EXTRACTVALUE(", "UPDATEXML(", "EXP(~(",
    ]

    AUTH_BYPASS_INJECTION = [
        "' OR '1'='1", "' OR 1=1--", "' OR 'X'='X",
        "ADMIN'--", "' OR ''='", "1' OR '1'='1",
        "' OR 1=1#", "' OR 1=1/*", "' OR TRUE--", "' OR TRUE#",
    ]

    WAF_BYPASS_OBFUSCATION = [
        "%27", "%20OR%20", "%20AND%20", "%20UNION%20", "%20SELECT%20",
        "CHAR(", "CHR(", "ASCII(", "/**/", "/**_**/",
        "%23NULL%0A", "%23QA%0A%23%0A",
        "/*️⃣*/",  # emoji WAF bypass
        "0X3127", "0X3227", "0X3327", "0X3427",
        "0X32204F524445522042592031",
        "0X32204F524445522042592032",
        "0X32204F524445522042592033",
    ]

    COMMENT_SEQUENCE_INJECTION = [
        "--", "-- -", "#", "/*", "*/", "/*!",
    ]

    DB_FINGERPRINTING = [
        "@@VERSION", "@@HOSTNAME", "@@DATADIR",
        "VERSION()", "USER()", "DATABASE()", "SCHEMA()",
        "CURRENT_USER", "SYSTEM_USER", "SESSION_USER",
        "INFORMATION_SCHEMA", "SYSOBJECTS", "SYSCOLUMNS",
        "SYS.TABLES", "SYS.COLUMNS",
        "SELECT BANNER FROM V$VERSION",
        "SELECT VERSION FROM V$INSTANCE",
    ]

    MSSQL_SPECIFIC_INJECTION = [
        "XP_CMDSHELL", "XP_REGREAD", "OPENROWSET(",
        "OPENDATASOURCE(", "BULK INSERT", "SP_MAKEWEBTASK",
        "SP_EXECUTESQL", "MASTER..XP_DIRTREE",
        "DECLARE @P VARCHAR", "SET @P=(",
    ]

    ORACLE_SPECIFIC_INJECTION = [
        "UTL_HTTP", "UTL_FILE", "UTL_INADDR",
        "UTL_INADDR.GET_HOST_ADDRESS(", "DBMS_PIPE",
        "ALL_TABLES", "ALL_COLUMNS",
        "EXTRACTVALUE(XMLTYPE(", "FROM DUAL",
        "<!DOCTYPE ROOT", "<!ENTITY % REMOTE SYSTEM",
    ]

    POSTGRESQL_SPECIFIC_INJECTION = [
        "COPY (SELECT", "TO PROGRAM", "NSLOOKUP",
        "CREATE OR REPLACE FUNCTION", "LANGUAGE PLPGSQL",
        "SECURITY DEFINER", "LO_IMPORT", "LO_EXPORT",
    ]

    MYSQL_SPECIFIC_INJECTION = [
        "LOAD_FILE(", "INTO OUTFILE", "INTO DUMPFILE",
    ]

    OOB_DNS_EXFILTRATION = [
        "XP_DIRTREE", "EXEC MASTER..XP_DIRTREE",
        "UTL_INADDR.GET_HOST_ADDRESS(",
        "COPY (SELECT", "NSLOOKUP",
        "LOAD_FILE(CONCAT", "INTO OUTFILE '/TMP",
        "DECLARE C TEXT", "DECLARE P TEXT",
        "EXECUTE C", "\\\\\\\\",
    ]

    STACKED_QUERY_INJECTION = [
        ";SELECT", "; SELECT", ";DROP",
        "; DROP", ";INSERT", ";UPDATE", ";EXEC",
    ]

    # ---- map technique name to its pattern list ----
    TECHNIQUE_MAP = {
        "KEYWORD_INJECTION": KEYWORD_INJECTION,
        "KEYWORD_HEX_ENCODED": KEYWORD_HEX_ENCODED,
        "UNION_BASED_INJECTION": UNION_BASED_INJECTION,
        "BLIND_TIME_BASED_INJECTION": BLIND_TIME_BASED_INJECTION,
        "BLIND_BOOLEAN_BASED_INJECTION": BLIND_BOOLEAN_BASED_INJECTION,
        "ERROR_BASED_INJECTION": ERROR_BASED_INJECTION,
        "AUTH_BYPASS_INJECTION": AUTH_BYPASS_INJECTION,
        "WAF_BYPASS_OBFUSCATION": WAF_BYPASS_OBFUSCATION,
        "COMMENT_SEQUENCE_INJECTION": COMMENT_SEQUENCE_INJECTION,
        "DB_FINGERPRINTING": DB_FINGERPRINTING,
        "MSSQL_SPECIFIC_INJECTION": MSSQL_SPECIFIC_INJECTION,
        "ORACLE_SPECIFIC_INJECTION": ORACLE_SPECIFIC_INJECTION,
        "POSTGRESQL_SPECIFIC_INJECTION": POSTGRESQL_SPECIFIC_INJECTION,
        "MYSQL_SPECIFIC_INJECTION": MYSQL_SPECIFIC_INJECTION,
        "OOB_DNS_EXFILTRATION": OOB_DNS_EXFILTRATION,
        "STACKED_QUERY_INJECTION": STACKED_QUERY_INJECTION,
    }

    hits = []
    for tech, patterns in TECHNIQUE_MAP.items():
        for pattern in patterns:
            if pattern in param:
                hits.append((tech, pattern))
                break

    if hits:
        for technique, matched in hits:
            print(Colors.red(f"[!] DETECTED: {tech} — matched: '{matched}'"))
    else:
        print(Colors.green("[✓] Clean"))

    return hits




def SQLi_decode_cond(params):


    if params != unquote(params):
        decoded_url = unquote(params)
        print(Colors.yellow(f"[*] Seems to be URL encoded. Decoding...."))
        analyse_pattern = SQLi_patterns(params)


    else:
        print("[*] Already decoded, Perfoming pattern matching")
        analyse_pattern = SQLi_patterns(params)

-- ============================================================================
-- WARSZTAT SNOWFLAKE: ShopPulse Express – Bezpieczna Analityka e-Commerce
-- Podręczny skrypt SQL krok po kroku
-- ============================================================================

-- ----------------------------------------------------------------------------
-- KROK 0: Inicjalizacja Środowiska i Wygenerowanie Danych Testowych
-- ----------------------------------------------------------------------------

-- 1. Tworzenie bazy danych i schematu
CREATE DATABASE IF NOT EXISTS SHOPPULSE_DB;
USE DATABASE SHOPPULSE_DB;
CREATE SCHEMA IF NOT EXISTS WORKSHOP_SCH;
USE SCHEMA WORKSHOP_SCH;

-- 2. Tabela wymiarowa produktów (dim_products)
CREATE OR REPLACE TABLE dim_products (
    sku_code VARCHAR(20),
    category VARCHAR(50),
    unit_price NUMBER(10,2)
);

INSERT INTO dim_products VALUES
('SKU-101', 'Electronics', 1200.00),
('SKU-102', 'Electronics', 150.00),
('SKU-201', 'Apparel', 89.90),
('SKU-301', 'Home & Kitchen', 45.00);

-- 3. Surowe dane e-commerce z danymi zagnieżdżonymi w JSON (raw_orders_json)
CREATE OR REPLACE TABLE raw_orders_json (
    order_id INT,
    customer_name VARCHAR(100),
    customer_email VARCHAR(100),
    national_id VARCHAR(20), -- PESEL (PII)
    region VARCHAR(50),
    order_timestamp TIMESTAMP_NTZ,
    order_payload VARIANT
);

INSERT INTO raw_orders_json
SELECT 1001, 'Jan Kowalski', 'jan.kowalski@poczta.pl', '85010112345', 'Wielkopolskie', '2026-03-20 10:15:00',
    PARSE_JSON('{"currency": "PLN", "items": [{"sku": "SKU-101", "qty": 1, "tags": ["express", "fragile"]}, {"sku": "SKU-102", "qty": 2}], "discount": 0.05}')
UNION ALL
SELECT 1002, 'Anna Nowak', 'anna.nowak@firma.pl', '92051567890', 'Mazowieckie', '2026-03-20 11:30:00',
    PARSE_JSON('{"currency": "PLN", "items": [{"sku": "SKU-201", "qty": 3, "tags": ["promo"]}], "discount": 0.10}')
UNION ALL
SELECT 1003, 'Piotr Wiśniewski', 'piotr.w@domain.com', '78123054321', 'Wielkopolskie', '2026-03-20 12:00:00',
    PARSE_JSON('{"currency": "PLN", "items": [], "discount": 0.00}')
UNION ALL
SELECT 1004, 'Ewa Kamińska', 'ewa.k@poczta.pl', '95081234567', 'Małopolskie', '2026-03-20 14:20:00',
    PARSE_JSON('{"currency": "PLN", "items": [{"sku": "SKU-301", "qty": 5, "tags": []}, {"sku": "SKU-102", "qty": 1, "tags": ["express"]}]}')
UNION ALL
SELECT 1005, 'Tomasz Zieliński', 'tomasz.z@firma.pl', '88030498765', 'Mazowieckie', '2026-03-20 15:45:00',
    PARSE_JSON(null);

-- 4. Stan magazynowy produktów (inventory_stock)
CREATE OR REPLACE TABLE inventory_stock (
    product_id INT,
    sku_code VARCHAR(20),
    stock_qty INT,
    warehouse_location VARCHAR(50),
    last_updated TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

INSERT INTO inventory_stock VALUES
(1, 'SKU-101', 50, 'Poznań-1', CURRENT_TIMESTAMP()),
(2, 'SKU-102', 120, 'Warszawa-2', CURRENT_TIMESTAMP()),
(3, 'SKU-201', 200, 'Poznań-1', CURRENT_TIMESTAMP()),
(4, 'SKU-301', 80, 'Kraków-1', CURRENT_TIMESTAMP());

-- 5. Tabela uprawnień regionalnych (user_region_map)
CREATE OR REPLACE TABLE user_region_map (
    user_name VARCHAR(100),
    assigned_region VARCHAR(50)
);

INSERT INTO user_region_map VALUES (CURRENT_USER(), 'Wielkopolskie');

-- PUNKT KONTROLNY KROK 0:
SELECT COUNT(*) AS total_orders FROM raw_orders_json; -- Oczekiwano: 5
SELECT COUNT(*) AS total_inventory FROM inventory_stock; -- Oczekiwano: 4


-- ----------------------------------------------------------------------------
-- KROK 1: Kontrola Dostępu (RBAC), Maskowanie PII i Row Access Policy
-- ----------------------------------------------------------------------------

-- 1. Tworzenie ról i przyznanie uprawnień
USE ROLE USERADMIN;
CREATE ROLE IF NOT EXISTS ANALYST_EU;
CREATE ROLE IF NOT EXISTS PII_AUDITOR;

SELECT CURRENT_USER();

USE ROLE SECURITYADMIN;
GRANT ROLE ANALYST_EU TO USER <user>;
GRANT ROLE PII_AUDITOR TO USER <user>;


GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE ANALYST_EU;
GRANT USAGE ON DATABASE SHOPPULSE_DB TO ROLE ANALYST_EU;
GRANT USAGE ON SCHEMA SHOPPULSE_DB.WORKSHOP_SCH TO ROLE ANALYST_EU;
GRANT SELECT ON ALL TABLES IN SCHEMA SHOPPULSE_DB.WORKSHOP_SCH TO ROLE ANALYST_EU;

-- 2. Polityki maskowania (Dynamic Data Masking)
USE ROLE ACCOUNTADMIN;
CREATE OR REPLACE MASKING POLICY mask_email_custom AS (val VARCHAR) RETURNS VARCHAR ->
  -- wypełnij
	jeśli rola jest inna nież PII_AUDITOR to REGEXP_REPLACE(val, '^([^@]{1})[^@]+', '\\1***')
  ---

CREATE OR REPLACE MASKING POLICY mask_pesel_custom AS (val VARCHAR) RETURNS VARCHAR ->
  ---wypełnij
	jeśli rola jest inna nież PII_AUDITOR to '******' || RIGHT(val, 5)
  --

-- 3. Nałożenie polityk maskowania
ALTER TABLE raw_orders_json MODIFY COLUMN -- wypełnij;
ALTER TABLE raw_orders_json MODIFY COLUMN -- wypełnij;

-- 4. Row Access Policy (Bezpieczeństwo na poziomie wiersza)
CREATE OR REPLACE ROW ACCESS POLICY rap_region_security AS (reg VARCHAR) RETURNS BOOLEAN ->
  IS_ROLE_IN_SESSION('ACCOUNTADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') OR
  EXISTS (
    SELECT 1 FROM user_region_map m 
    WHERE UPPER(m.user_name) = CURRENT_USER() AND --- wypełnij ---
  );

ALTER TABLE raw_orders_json ADD ROW ACCESS POLICY rap_region_security ON (region);

-- PUNKT KONTROLNY KROK 1:
/*
UWAGA:
Role drugorzędne (secondary roles). W Snowsight użytkownicy mają domyślnie włączone wszystkie role drugorzędne (ALL). 
Jeśli masz nadaną PII_AUDITOR, jest ona aktywna w tle, nawet gdy na górze wybrana jest inna rola. Do testów wyłącz je:

	USE SECONDARY ROLES NONE;
	SELECT * FROM raw_orders_json;
*/
USE ROLE ANALYST_EU;
USE WAREHOUSE COMPUTE_WH;
SELECT customer_name, customer_email, national_id, region FROM raw_orders_json;
-- Oczekiwano: 2 wiersze z regionu 'Wielkopolskie', z zamaskowanym e-mailem oraz PESEL.


-- ----------------------------------------------------------------------------
-- KROK 2: Przetwarzanie Danych JSON i LATERAL FLATTEN
-- ----------------------------------------------------------------------------
USE ROLE ACCOUNTADMIN;

-- Zapytanie spłaszczające zagnieżdżony JSON z obsługą brakujących wartości (outer => TRUE)
WITH flat_orders AS (
    SELECT 
        o.order_id,
        o.customer_name,
        f_item.value:sku::STRING AS sku_code,
        f_item.value:qty::INT AS quantity,
        f_tag.value::STRING AS item_tag,
        --- wypełnij --- AS discount_rate
    FROM raw_orders_json o,
    LATERAL FLATTEN(input => --- wypełnij ---) f_item,
    LATERAL FLATTEN(input => f_item.value:tags, outer => TRUE) f_tag
)
SELECT 
    fo.order_id,
    fo.sku_code,
    p.category,
    fo.quantity,
    p.unit_price,
    (fo.quantity * p.unit_price) AS line_gross,
    (fo.quantity * p.unit_price) * (1 - fo.discount_rate) AS line_net,
    fo.item_tag
FROM flat_orders fo
LEFT JOIN dim_products p ON fo.sku_code = p.sku_code;

-- PUNKT KONTROLNY KROK 2:
SELECT COUNT(DISTINCT o.order_id) AS total_processed_orders
FROM raw_orders_json o,
LATERAL FLATTEN(input => o.order_payload:items, outer => TRUE) f_item;
-- Oczekiwano: 5 zamówień przetworzonych (dzięki outer => TRUE).


-- ----------------------------------------------------------------------------
-- KROK 3: Architektura Obiektów – Temporary, Transient, Secure View, Dynamic Table
-- ----------------------------------------------------------------------------

-- 1. Temporary Table (Dostępna tylko w ramach aktywnej sesji)
CREATE OR REPLACE TEMPORARY TABLE TMP_STAGE_CALCULATIONS AS
SELECT 
    o.order_id,
    f_item.value:sku::STRING AS sku_code,
    f_item.value:qty::INT AS quantity,
    p.category,
    p.unit_price,
    (f_item.value:qty::INT * p.unit_price) AS line_gross
FROM raw_orders_json o,
LATERAL FLATTEN(--- wypełnij ---) f_item
JOIN dim_products p ON f_item.value:sku::STRING = p.sku_code;

-- 2. Transient Table (Trwała tarcza bez opłacanego Fail-Safe)
CREATE OR REPLACE TRANSIENT TABLE STG_DAILY_SALES (
    order_id INT,
    sku_code VARCHAR(20),
    quantity INT,
    line_gross NUMBER(10,2)
) --- wypełnij ustaw 1 dzień retencji ---;

INSERT INTO STG_DAILY_SALES 
SELECT order_id, sku_code, quantity, line_gross FROM TMP_STAGE_CALCULATIONS;

-- 3. Secure View (Bezpieczny widok ukrywający definicję SQL)
CREATE OR REPLACE --- wypełnij --- SEC_V_CUSTOMER_STATS AS
SELECT 
    customer_name,
    region,
    COUNT(order_id) AS total_orders
FROM raw_orders_json
GROUP BY customer_name, region;

-- 4. Dynamic Table (Automatyczne odświeżanie potoku danych)
CREATE OR REPLACE DYNAMIC TABLE DT_CATEGORY_SUMMARY
--- wypełnij ustaw target lag na 1 minutę---
WAREHOUSE = COMPUTE_WH
AS
SELECT 
    p.category,
    SUM(f_item.value:qty::INT) AS total_qty_sold,
    SUM(f_item.value:qty::INT * p.unit_price) AS total_revenue
FROM raw_orders_json o,
LATERAL FLATTEN(input => o.order_payload:items) f_item
JOIN dim_products p ON f_item.value:sku::STRING = p.sku_code
GROUP BY p.category;

-- PUNKT KONTROLNY KROK 3:
SELECT TABLE_NAME, IS_TRANSIENT, RETENTION_TIME 
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_NAME IN ('STG_DAILY_SALES', 'RAW_ORDERS_JSON');

SELECT * FROM DT_CATEGORY_SUMMARY;


-- ----------------------------------------------------------------------------
-- KROK 4: Streamy, Time Travel i Odzyskiwanie Awaryjne (Fail-Safe)
-- ----------------------------------------------------------------------------

-- 1. Utworzenie Streamu CDC
CREATE OR REPLACE STREAM inventory_changes_stream ON TABLE inventory_stock;

-- 2. Symulacja awarii (Błędna aktualizacja danych)
UPDATE inventory_stock 
SET stock_qty = 0 
WHERE warehouse_location = 'Poznań-1';

-- 3. Podgląd rejestru zmian w Streamie
SELECT sku_code, stock_qty, METADATA$ACTION, METADATA$ISUPDATE, METADATA$ROW_ID 
FROM -- wypełnij ---;

-- 4. Odczyt historycznego stanu danych przed awarią (Time Travel)
SELECT * FROM inventory_stock -- wypełnij ---;

-- 5. Przywrócenie pierwotnego stanu tabeli z wykorzystaniem CTAS i Time Travel
CREATE OR REPLACE TABLE inventory_stock AS
-- wypełnij ---;

-- PUNKT KONTROLNY KROK 4:
SELECT * FROM inventory_stock WHERE warehouse_location = 'Poznań-1';
-- Oczekiwano: Przywrócono wartości stock_qty = 50 oraz 200.


-- ----------------------------------------------------------------------------
-- KROK 5: Walidacja Końcowa Środowiska
-- ----------------------------------------------------------------------------

SELECT 'raw_orders_json' AS obiekt, COUNT(*) AS ilosc_rekordow FROM raw_orders_json
UNION ALL
SELECT 'inventory_stock' AS obiekt, COUNT(*) AS ilosc_rekordow FROM inventory_stock
UNION ALL
SELECT 'STG_DAILY_SALES' AS obiekt, COUNT(*) AS ilosc_rekordow FROM STG_DAILY_SALES;

--Sprzątanie
drop database shoppulse_db;

--KONIEC :)
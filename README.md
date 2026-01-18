# CMS API për Menaxhimin e Përdoruesve

Një RESTful API i fuqishëm i krijuar për autentifikimin dhe menaxhimin e përdoruesve, duke lehtësuar qasjen e sigurt përmes 'JWT tokens' dhe Autentifikimit me Dy Faktorë (2FA).

## 🚀 Veçoritë

- **Autentifikimi**: Kyçje (login) dhe regjistrim i sigurt me 'JWT Bearer tokens' dhe 'Refresh Tokens'.
- **Autentifikimi me Dy Faktorë**: Integrim i 2FA i bazuar në TOTP (Google Authenticator, etj.).
- **Menaxhimi i Përdoruesve**: Aftësi administrative për të kërkuar, përditësuar dhe menaxhuar llogaritë e përdoruesve.
- **Siguria**: Kontroll i qasjes i bazuar në role (RBAC) dhe trajtim i sigurt i fjalëkalimeve.

## 🔐 Autentifikimi

| Lloji          | Header                          | Përdorimi                                                                |
| -------------- | ------------------------------- | ------------------------------------------------------------------------ |
| **JWT Bearer** | `Authorization: Bearer <token>` | Endpoint-et e mbrojtura (Profili i përdoruesit, Menaxhimi i përdoruesve) |

## 📡 Përmbledhje e Endpoints

### Autentifikimi dhe Llogaria

_Menaxhoni identitetin e përdoruesit dhe cilësimet e sigurisë._

- `POST /api/User/register` - Regjistro një përdorues të ri.
- `GET /api/User/login` - Kyçje me email dhe fjalëkalim.
- `POST /api/User/logout` - Zhvlerëso sesionin e përdoruesit.
- `GET /api/User/refresh-token` - Merr një 'access token' të ri.
- `PUT /api/User/update-account` - Përditëso detajet e llogarisë personale.
- `GET /api/User/account-info` - Merr informacionin e përdoruesit aktual.

### Autentifikimi me Dy Faktorë

_Rritni sigurinë me 2FA._

- `POST /api/User/generate-two-factor-auth-code` - Gjenero një kod konfigurimi/URL për QR.
- `POST /api/User/two-factor-auth-confirm` - Verifiko dhe aktivizo 2FA.
- `DELETE /api/User/disable-two-factor-auth` - Çaktivizo 2FA.
- `POST /api/User/login-with-two-factor-auth` - Hapi i dytë i verifikimit për kyçje.

### Menaxhimi i Përdoruesve

_Endpoint-et administrative për menaxhimin e përdoruesve të sistemit._

- `GET /api/UserManagement` - Listo të gjithë përdoruesit.
- `GET /api/UserManagement/{id}` - Merr detajet e përdoruesit.
- `PUT /api/UserManagement/{id}` - Përditëso rolin ose detajet e një përdoruesi.
- `DELETE /api/UserManagement/{id}` - Fshi një përdorues.
- `GET /api/UserManagement/search` - Kërko përdorues sipas email-it, emrit të përdoruesit, etj.
- `POST /api/UserManagement/delete-bulk` - Fshi disa përdorues njëkohësisht.

## 🛠️ Shembuj Përdorimi

### Kyçja

```bash
curl -X GET "http://localhost:5055/api/User/login?email=user@example.com&password=password123"
```

### Regjistrimi i Përdoruesit

```bash
curl -X POST "http://localhost:5055/api/User/register" \
     -H "Content-Type: application/json" \
     -d '{
           "email": "user@example.com",
           "username": "user1",
           "password": "password123"
         }'
```

## 🏗️ Zhvillimi

### Parakushtet

- .NET 8.0 SDK
- Docker (për MySQL & Redis)

### Struktura e Bazës së Të Dhënave

### Struktura e Bazës së Të Dhënave

Baza e të dhënave përbëhet nga tabelat e mëposhtme, të dizajnuara për të mbështetur sigurinë dhe menaxhimin e përdoruesve:

#### 1. Tabela `Users`

Ruaj llogaritë e përdoruesve dhe kredencialet e tyre.

| Kolona                 | Tipi        | Përshkrimi                                             |
| :--------------------- | :---------- | :----------------------------------------------------- |
| **Id**                 | `GUID` (PK) | Identifikues unik për përdoruesin.                     |
| **Email**              | `VARCHAR`   | Email-i i përdoruesit (duhet të jetë unik).            |
| **Username**           | `VARCHAR`   | Emri i shfrytëzuesit.                                  |
| **Password**           | `VARCHAR`   | Fjalëkalimi i kriptuar (Hashed).                       |
| **TwoFactorSecret**    | `VARCHAR?`  | Çelësi sekret për gjenerimin e kodeve TOTP.            |
| **IsTwoFactorEnabled** | `BOOLEAN`   | Tregues nëse 2FA është aktivizuar.                     |
| **IsAdmin**            | `BOOLEAN`   | Përcakton nëse përdoruesi ka të drejta administrative. |

#### 2. Tabela `RefreshTokens`

Përdoret për të menaxhuar sesionet afatgjata dhe rinovimin e token-ave pa kërkuar fjalëkalimin.

| Kolona      | Tipi        | Përshkrimi                            |
| :---------- | :---------- | :------------------------------------ |
| **Id**      | `GUID` (PK) | Identifikues unik i token-it.         |
| **UserId**  | `GUID` (FK) | Lidhje me tabelën `Users`.            |
| **Expires** | `DATETIME`  | Data dhe koha e skadimit të token-it. |

#### 3. Tabela `TwoFactorAuthCodes`

Përdoret gjatë procesit të verifikimit ose konfigurimit të autentifikimit me dy faktorë.

| Kolona      | Tipi        | Përshkrimi                              |
| :---------- | :---------- | :-------------------------------------- |
| **Id**      | `GUID` (PK) | Identifikues unik.                      |
| **UserId**  | `GUID` (FK) | Lidhje me tabelën `Users`.              |
| **Expires** | `DATETIME`  | Data e skadimit të kodit të përkohshëm. |

Databaza menaxhohet përmes **Entity Framework Core Migrations**, duke siguruar që struktura të jetë gjithmonë e sinkronizuar me kodin.

### Ekzekutimi Lokalisht

1. Nis shërbimet e infrastrukturës:
   ```bash
   docker compose up -d
   ```
2. API do të jetë i disponueshëm në `http://localhost:5055`.
3. Shiko dokumentacionin Swagger në `http://localhost:5055/swagger`.

## ✅ Përmbushja e Kërkesave Teknike

Ky projekt i përmbahet kërkesave strikte teknike për kursin "Zhvillimi i Ueb Shërbimeve & Ueb API-ve".

### 1. Arkitektura e Sistemit

- **Mikroshërbime & REST**: Projektuar si një mikroshërbim i pavarur për Menaxhimin e Identitetit. Ekspozon një API plotësisht RESTful duke përdorur foljet standarde HTTP dhe 'payloads' JSON.
- **Pa gjendje (Statelessness)**: API është plotësisht pa gjendje, duke u mbështetur në JWT për të bartur informacionet e përdoruesit.

### 2. Siguria

- **Autentifikimi dhe Autorizimi**: Implementon standardet **OAuth 2.0 / JWT** për qasje të sigurt.
- **MFA**: Mbështetje për **Autentifikimin me Dy Faktorë (TOTP)** për siguri të shtuar.
- **RBAC**: Logjika e Kontrollit të Qasjes Bazuar në Role (RBAC) izolon aftësitë e Adminit nga Përdoruesit standardë.
- **Mbrojtja e Të Dhënave**: Fjalëkalimet ruhen në mënyrë të sigurt (hash). HTTPS është e detyrueshme në ambientet e prodhimit.

### 3. Performanca dhe Shkallëzueshmëria

- **Strategjia e Caching**: **Redis** është implementuar për të ruajtur të dhënat që kërkohen shpesh dhe listat e lejimit/ndalimit të token-ave.
- **Async/Await**: Përdorim universal i programimit asinkron në C# për të përballuar konkurrencën e lartë.

### 4. Dokumentimi i API-ve

- **OpenAPI / Swagger**: Sistemi gjeneron automatikisht dokumentacionin OAS 3.0.
- **Ndërfaqe Interaktive**: Swagger UI i integruar lejon testimin në kohë reale të endpoint-eve.

### 5. Versionimi

- **Evoluimi**: API është strukturuar për të mbështetur versionimin (p.sh., `v1` në metadata) për të siguruar përputhshmëri të prapambetur për ndryshimet e ardhshme.

### 6. Integrimet

- **Databaza**: Integrim me **MySQL** përmes Entity Framework Core.
- **Kontejnerizimi**: Integrim i plotë me ekosistemet **Docker**.

### 7. Standardet e Kodimit

- **Arkitekturë e Pastër**: Ndarje strikte e përgjegjësive (Domain, Application, Infrastructure, API).
- **SOLID**: Përdorim i Injeksionit të Varësisë (DI) dhe Ndarjes së Ndërfaqeve në të gjithë kodin.

### 8. Platforma dhe Teknologjitë

- **Backend**: Ndërtuar me **.NET 8** (Framework ndër-platformësh me performancë të lartë).
- **Ruajtja**: MySQL 8.0 & Redis 7.
- **DevOps**: Docker Compose për orkestrim.

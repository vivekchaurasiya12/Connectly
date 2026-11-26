
@echo off
setlocal

echo.
echo ==========================================
echo       CONNECTLY - AUTH SERVICE STARTUP
echo ==========================================
echo.

REM 1. Navigate to Connectly project root
set "ROOT=%~dp0.."
pushd "%ROOT%"

REM 2. Check root environment file
if not exist ".env" (
    echo ERROR: Root .env file not found.
    goto :error
)

REM 3. Load environment variables from root .env
for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
    if not "%%A"=="" set "%%A=%%B"
)

REM 4. Validate required database variables
if not defined DB_NAME (
    echo ERROR: DB_NAME is missing in .env
    goto :error
)

if not defined DB_USERNAME (
    echo ERROR: DB_USERNAME is missing in .env
    goto :error
)

if not defined DB_PASSWORD (
    echo ERROR: DB_PASSWORD is missing in .env
    goto :error
)

if not defined DB_URL (
    echo ERROR: DB_URL is missing in .env
    goto :error
)

REM 5. Start PostgreSQL using Docker Compose
echo [1/3] Starting PostgreSQL...

docker compose --env-file .env -f infrastructure/docker/docker-compose.yml up -d

if errorlevel 1 (
    echo ERROR: Failed to start PostgreSQL.
    goto :error
)

REM 6. Wait until PostgreSQL is ready
echo.
echo [2/3] Waiting for PostgreSQL...

set /a ATTEMPTS=0

:wait_for_postgres

docker exec connectly-postgres pg_isready -U "%DB_USERNAME%" -d "%DB_NAME%" >nul 2>&1

if not errorlevel 1 goto :postgres_ready

set /a ATTEMPTS+=1

if %ATTEMPTS% GEQ 30 (
    echo ERROR: PostgreSQL did not become ready.
    goto :error
)

timeout /t 2 /nobreak >nul
goto :wait_for_postgres

:postgres_ready

echo PostgreSQL is ready.

REM 7. Start Auth Service
echo.
echo [3/3] Starting Auth Service...

cd /d "%ROOT%\backend\auth-service"

if not exist "mvnw.cmd" (
    echo ERROR: Maven Wrapper not found.
    goto :error
)

call mvnw.cmd spring-boot:run

goto :finish

:error
echo.
echo Startup failed. Check the error above.
pause

:finish
popd
endlocal

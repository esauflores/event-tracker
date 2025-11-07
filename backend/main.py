import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status, Request, Response, Form
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from prisma import Prisma
from pwdlib import PasswordHash

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await prisma.connect()
    yield
    await prisma.disconnect()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI(title="Login Python Implementation", version="1.0.0", lifespan=lifespan)

# Static files and templates
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(os.getcwd(), "../frontend")),
    name="static",
)
templates = Jinja2Templates(directory=os.path.join(os.getcwd(), "../frontend"))

prisma = Prisma()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
IS_PRODUCTION = os.getenv("ENVIRONMENT") == "production"

ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 15

#### Authentication Utilities ####
password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return password_hash.verify(password, hashed)


def generate_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    issued_at = datetime.now(timezone.utc)
    to_encode = {"sub": username, "exp": expire, "iat": issued_at}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def decode_token(token: str) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception

    return payload


def _get_token_from_request(request: Request) -> str | None:
    auth: str | None = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        return auth.split(" ", 1)[1]
    return request.cookies.get("access_token")


##### Middleware #####


@app.middleware("http")
async def token_middleware(request: Request, call_next):
    token = _get_token_from_request(request)
    new_token = None
    if token:
        try:
            user_dict = decode_token(token)
            iat = user_dict.get("iat")
            sub = user_dict.get("sub")

            if iat and sub:
                issued_at = datetime.fromtimestamp(iat, tz=timezone.utc)
                now = datetime.now(timezone.utc)
                elapsed = now - issued_at
                if elapsed > timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES):
                    new_token = generate_token(sub)

                user = await prisma.user.find_first(where={"username": sub})
                request.state.user = user

        except HTTPException:
            request.state.user = None
    else:
        request.state.user = None

    response: Response = await call_next(request)

    if new_token:
        response.set_cookie(
            key="access_token",
            value=new_token,
            httponly=True,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            secure=IS_PRODUCTION,
            samesite="lax",
        )

    return response


##### Routes #####


@app.get("/", response_class=HTMLResponse)
async def root_page(request: Request):
    return RedirectResponse("/events")

    if getattr(request.state, "user", None):
        return templates.TemplateResponse(
            "index.html", {"request": request, "user": request.state.user}
        )

    return RedirectResponse("/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if getattr(request.state, "user", None):
        return RedirectResponse("/events")

    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/hx/login", response_class=HTMLResponse)
async def hx_login(username: str = Form(...), password: str = Form(...)):
    """HTMX-friendly login: accepts form data, sets HttpOnly cookie and returns HX-Redirect."""
    if not username or not password:
        return HTMLResponse("Missing fields", status_code=400)

    user = await prisma.user.find_first(where={"username": username})
    if not user or not verify_password(password, user.password):
        return HTMLResponse("Incorrect username or password", status_code=400)

    access_token = generate_token(user.username)
    max_age = ACCESS_TOKEN_EXPIRE_MINUTES * 60

    resp = HTMLResponse("ok")
    resp.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=max_age,
        expires=max_age,
        secure=IS_PRODUCTION,
        samesite="lax",
    )
    # instruct HTMX to navigate to the root (or change to /events/view)
    resp.headers["HX-Redirect"] = "/"
    return resp


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/hx/register", response_class=HTMLResponse)
async def hx_register(
    username: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    """HTMX-friendly registration: accepts form data, creates user, sets HttpOnly cookie and returns HX-Redirect."""
    if not username or not name or not email or not password:
        return HTMLResponse("Missing fields", status_code=400)

    existing_user = await prisma.user.find_first(
        where={"OR": [{"username": username}, {"email": email}]}
    )
    if existing_user:
        return HTMLResponse("Username or email already taken", status_code=400)

    hashed_password = hash_password(password)
    user = await prisma.user.create(
        data={
            "username": username,
            "name": name,
            "email": email,
            "password": hashed_password,
        }
    )

    access_token = generate_token(user.username)
    max_age = ACCESS_TOKEN_EXPIRE_MINUTES * 60

    resp = HTMLResponse("ok")
    resp.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=max_age,
        expires=max_age,
        secure=IS_PRODUCTION,
        samesite="lax",
    )
    # instruct HTMX to navigate to the root (or change to /events/view)
    resp.headers["HX-Redirect"] = "/"
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/")
    resp.delete_cookie("access_token")
    return resp


##### Event Management with HTMX ####


@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    """Main events page."""
    user = getattr(request.state, "user", None)
    if not user:
        return RedirectResponse("/login")

    return templates.TemplateResponse(
        "events.html",
        {"request": request, "user": user},
    )


@app.get("/hx/events/view", response_class=HTMLResponse)
async def hx_view_events(request: Request):
    """HTMX-friendly event listing."""
    user = getattr(request.state, "user", None)
    if not user:
        return HTMLResponse("Unauthorized", status_code=401)

    events = await prisma.event.find_many(
        where={"user_id": user.id}, order={"date": "asc"}
    )

    # convert to just date
    for event in events:
        event.date = event.date.strftime("%Y-%m-%d")

    # remove events past today
    today = datetime.now(timezone.utc).date()
    events = [
        event for event in events if datetime.fromisoformat(event.date).date() >= today
    ]

    return templates.TemplateResponse(
        "events_list.html",
        {"request": request, "events": events, "user": user},
    )


@app.post("/hx/events/create", response_class=HTMLResponse)
async def hx_create_event_form(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    date: str = Form(...),
):
    """HTMX-friendly event creation form."""
    user = getattr(request.state, "user", None)
    if not user:
        return HTMLResponse("Unauthorized", status_code=401)

    date = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc).isoformat()

    event = await prisma.event.create(
        data={
            "title": title,
            "description": description,
            "date": date,
            "user": {"connect": {"id": user.id}},
        }
    )

    return RedirectResponse("/hx/events/view", status_code=303)


@app.delete("/hx/events/{event_id}/delete", response_class=HTMLResponse)
async def hx_delete_event(request: Request, event_id: int):
    """HTMX-friendly event deletion."""
    user = getattr(request.state, "user", None)
    if not user:
        return HTMLResponse("Unauthorized", status_code=401)

    event = await prisma.event.find_first(where={"id": event_id, "user_id": user.id})
    if not event:
        return HTMLResponse("Event not found", status_code=404)

    await prisma.event.delete(where={"id": event_id})

    return RedirectResponse("/hx/events/view", status_code=303)

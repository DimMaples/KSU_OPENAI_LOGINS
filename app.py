import json
import os
import logging
import requests
import openai
from dotenv import load_dotenv
from flask import Flask, Response, request, session ,jsonify, url_for, redirect, render_template
from authlib.integrations.flask_client import OAuth
#from werkzeug.middleware.proxy_fix import ProxyFix

import identity.web
from flask_session import Session

load_dotenv()

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SESSION_PERMANENT"] = False

#adding login page

app.config.update(
    SECRET_KEY=os.urandom(26)
)
#for MS-azure-login
Session(app)
oauth = OAuth(app)

auth = identity.web.Auth(
    session=session,
    authority=os.environ.get('authority', '1'),
    client_id=os.environ.get('client_idd', '1'),
    client_credential=os.environ.get('client_credential', '1')
)

@app.route('/google/')
def google():
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '1')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '1')
    CONF_URL = os.environ.get('CONF_URL', '1')
    
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
    # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token)
    #print(" Google User ", user)
    #put to session
    session['user'] = user
    session['token']  = token
    return redirect('/') #TO DO: change this when done coding
    
@app.route("/login")
def login():
    return render_template("login.html", version="1", **auth.log_in(
        ["User.ReadBasic.All"], # Have user consent to scopes during log-in
        redirect_uri="https://ksu24ai-restore-bf97.azurewebsites.net/.auth/login/aad/callback",
    ))

@app.route("/.auth/login/aad/callback")
def micro_redirect():
    result = auth.complete_log_in(request.args)
    if "error" in result:
        return redirect('/select-login')
    session["user"]  = 'here'
    session["token"] = 'token'

    return redirect("/")
   
@app.route("/select-login")
def select_login():
    return render_template("select.html") 

@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def static_file(path):
    #session["user"]  = 'here' 
    if "user" in session:
        #session["user"] = "GOTH"
        #session["token"] = "RRRR"
        #s_type = type(session)
        return app.send_static_file(path)
        #return render_template('/select.html', result=session)
    return render_template('/select.html', result=session)
#@app.route("/")
#def index():
#    return render_template("index.html")
#@app.route("/<path:path>")
#def static_file(path):
#    return app.send_static_file(path)
#check session. if has login token then output chat
#if not output select page
    #return app.send_static_file(path)
#check session. if has login token then output chat
#if not output select page auth_uri
#    if session['_auth_flow']:
#        return app.send_static_file(path)
    #    return render_template('/index.html', result=session)
#    else :
#        return render_template('/select.html')

# ACS Integration Settings
AZURE_SEARCH_SERVICE = os.environ.get("AZURE_SEARCH_SERVICE")
AZURE_SEARCH_INDEX = os.environ.get("AZURE_SEARCH_INDEX")
AZURE_SEARCH_KEY = os.environ.get("AZURE_SEARCH_KEY")
AZURE_SEARCH_USE_SEMANTIC_SEARCH = os.environ.get("AZURE_SEARCH_USE_SEMANTIC_SEARCH", "false")
AZURE_SEARCH_SEMANTIC_SEARCH_CONFIG = os.environ.get("AZURE_SEARCH_SEMANTIC_SEARCH_CONFIG", "default")
AZURE_SEARCH_TOP_K = os.environ.get("AZURE_SEARCH_TOP_K", 5)
AZURE_SEARCH_ENABLE_IN_DOMAIN = os.environ.get("AZURE_SEARCH_ENABLE_IN_DOMAIN", "true")
AZURE_SEARCH_CONTENT_COLUMNS = os.environ.get("AZURE_SEARCH_CONTENT_COLUMNS")
AZURE_SEARCH_FILENAME_COLUMN = os.environ.get("AZURE_SEARCH_FILENAME_COLUMN")
AZURE_SEARCH_TITLE_COLUMN = os.environ.get("AZURE_SEARCH_TITLE_COLUMN")
AZURE_SEARCH_URL_COLUMN = os.environ.get("AZURE_SEARCH_URL_COLUMN")

# AOAI Integration Settings
AZURE_OPENAI_RESOURCE = os.environ.get("AZURE_OPENAI_RESOURCE")
AZURE_OPENAI_MODEL = os.environ.get("AZURE_OPENAI_MODEL")
AZURE_OPENAI_KEY = os.environ.get("AZURE_OPENAI_KEY")
AZURE_OPENAI_TEMPERATURE = os.environ.get("AZURE_OPENAI_TEMPERATURE", 0)
AZURE_OPENAI_TOP_P = os.environ.get("AZURE_OPENAI_TOP_P", 1.0)
AZURE_OPENAI_MAX_TOKENS = os.environ.get("AZURE_OPENAI_MAX_TOKENS", 1000)
AZURE_OPENAI_STOP_SEQUENCE = os.environ.get("AZURE_OPENAI_STOP_SEQUENCE")
AZURE_OPENAI_SYSTEM_MESSAGE = os.environ.get("AZURE_OPENAI_SYSTEM_MESSAGE", "You are an AI assistant that helps people find information.")
AZURE_OPENAI_PREVIEW_API_VERSION = os.environ.get("AZURE_OPENAI_PREVIEW_API_VERSION", "2023-06-01-preview")
AZURE_OPENAI_STREAM = os.environ.get("AZURE_OPENAI_STREAM", "true")
AZURE_OPENAI_MODEL_NAME = os.environ.get("AZURE_OPENAI_MODEL_NAME", "gpt-35-turbo") # Name of the model, e.g. 'gpt-35-turbo' or 'gpt-4'

SHOULD_STREAM = AZURE_OPENAI_STREAM.lower() == "true"

def is_chat_model():
    return (
        'gpt-4' in AZURE_OPENAI_MODEL_NAME.lower()
        or AZURE_OPENAI_MODEL_NAME.lower()
        in ['gpt-35-turbo-4k', 'gpt-35-turbo-16k']
    )

def should_use_data():
    return bool(AZURE_SEARCH_SERVICE and AZURE_SEARCH_INDEX and AZURE_SEARCH_KEY)

def prepare_body_headers_with_data(request):
    # sourcery skip: boolean-if-exp-identity, remove-unnecessary-cast
    request_messages = request.json["messages"]

    body = {
        "messages": request_messages,
        "temperature": float(AZURE_OPENAI_TEMPERATURE),
        "max_tokens": int(AZURE_OPENAI_MAX_TOKENS),
        "top_p": float(AZURE_OPENAI_TOP_P),
        "stop": AZURE_OPENAI_STOP_SEQUENCE.split("|")
        if AZURE_OPENAI_STOP_SEQUENCE
        else None,
        "stream": SHOULD_STREAM,
        "dataSources": [
            {
                "type": "AzureCognitiveSearch",
                "parameters": {
                    "endpoint": f"https://{AZURE_SEARCH_SERVICE}.search.windows.net",
                    "key": AZURE_SEARCH_KEY,
                    "indexName": AZURE_SEARCH_INDEX,
                    "fieldsMapping": {
                        "contentField": AZURE_SEARCH_CONTENT_COLUMNS.split("|")
                        if AZURE_SEARCH_CONTENT_COLUMNS
                        else [],
                        "titleField": AZURE_SEARCH_TITLE_COLUMN
                        if AZURE_SEARCH_TITLE_COLUMN
                        else None,
                        "urlField": AZURE_SEARCH_URL_COLUMN
                        if AZURE_SEARCH_URL_COLUMN
                        else None,
                        "filepathField": AZURE_SEARCH_FILENAME_COLUMN
                        if AZURE_SEARCH_FILENAME_COLUMN
                        else None,
                    },
                    "inScope": AZURE_SEARCH_ENABLE_IN_DOMAIN.lower() == "true",
                    "topNDocuments": AZURE_SEARCH_TOP_K,
                    "queryType": "semantic"
                    if AZURE_SEARCH_USE_SEMANTIC_SEARCH.lower() == "true"
                    else "simple",
                    "semanticConfiguration": AZURE_SEARCH_SEMANTIC_SEARCH_CONFIG
                    if AZURE_SEARCH_USE_SEMANTIC_SEARCH.lower() == "true"
                    and AZURE_SEARCH_SEMANTIC_SEARCH_CONFIG
                    else "",
                    "roleInformation": AZURE_OPENAI_SYSTEM_MESSAGE,
                },
            }
        ],
    }

    chatgpt_url = f"https://{AZURE_OPENAI_RESOURCE}.openai.azure.com/openai/deployments/{AZURE_OPENAI_MODEL}"
    if is_chat_model():
        chatgpt_url += "/chat/completions?api-version=2023-03-15-preview"
    else:
        chatgpt_url += "/completions?api-version=2023-03-15-preview"

    headers = {
        'Content-Type': 'application/json',
        'api-key': AZURE_OPENAI_KEY,
        'chatgpt_url': chatgpt_url,
        'chatgpt_key': AZURE_OPENAI_KEY,
        "x-ms-useragent": "GitHubSampleWebApp/PublicAPI/1.0.0"
    }

    return body, headers


def stream_with_data(body, headers, endpoint):
    s = requests.Session()
    response = {
        "id": "",
        "model": "",
        "created": 0,
        "object": "",
        "choices": [{
            "messages": []
        }]
    }
    try:
        with s.post(endpoint, json=body, headers=headers, stream=True) as r:
            for line in r.iter_lines(chunk_size=10):
                if line:
                    lineJson = json.loads(line.lstrip(b'data:').decode('utf-8'))
                    if 'error' in lineJson:
                        yield json.dumps(lineJson).replace("\n", "\\n") + "\n"
                    response["id"] = lineJson["id"]
                    response["model"] = lineJson["model"]
                    response["created"] = lineJson["created"]
                    response["object"] = lineJson["object"]

                    role = lineJson["choices"][0]["messages"][0]["delta"].get("role")
                    if role == "tool":
                        response["choices"][0]["messages"].append(lineJson["choices"][0]["messages"][0]["delta"])
                    elif role == "assistant": 
                        response["choices"][0]["messages"].append({
                            "role": "assistant",
                            "content": ""
                        })
                    else:
                        deltaText = lineJson["choices"][0]["messages"][0]["delta"]["content"]
                        if deltaText != "[DONE]":
                            response["choices"][0]["messages"][1]["content"] += deltaText

                    yield json.dumps(response).replace("\n", "\\n") + "\n"
    except Exception as e:
        yield json.dumps({"error": str(e)}).replace("\n", "\\n") + "\n"


def conversation_with_data(request):
    body, headers = prepare_body_headers_with_data(request)
    endpoint = f"https://{AZURE_OPENAI_RESOURCE}.openai.azure.com/openai/deployments/{AZURE_OPENAI_MODEL}/extensions/chat/completions?api-version={AZURE_OPENAI_PREVIEW_API_VERSION}"

    if SHOULD_STREAM:
        return (
            Response(
                stream_with_data(body, headers, endpoint),
                mimetype='text/event-stream',
            )
            if request.method == "POST"
            else Response(None, mimetype='text/event-stream')
        )
    r = requests.post(endpoint, headers=headers, json=body)
    status_code = r.status_code
    r = r.json()

    return Response(json.dumps(r).replace("\n", "\\n"), status=status_code)

def stream_without_data(response):
    responseText = ""
    for line in response:
        deltaText = line["choices"][0]["delta"].get('content')
        if deltaText and deltaText != "[DONE]":
            responseText += deltaText

        response_obj = {
            "id": line["id"],
            "model": line["model"],
            "created": line["created"],
            "object": line["object"],
            "choices": [{
                "messages": [{
                    "role": "assistant",
                    "content": responseText
                }]
            }]
        }
        yield json.dumps(response_obj).replace("\n", "\\n") + "\n"


def conversation_without_data(request):
    openai.api_type = "azure"
    openai.api_base = f"https://{AZURE_OPENAI_RESOURCE}.openai.azure.com/"
    openai.api_version = "2023-03-15-preview"
    openai.api_key = AZURE_OPENAI_KEY

    request_messages = request.json["messages"]
    messages = [
        {
            "role": "system",
            "content": AZURE_OPENAI_SYSTEM_MESSAGE
        }
    ]

    messages.extend(
        {"role": message["role"], "content": message["content"]}
        for message in request_messages
    )
    response = openai.ChatCompletion.create(
        engine=AZURE_OPENAI_MODEL,
        messages = messages,
        temperature=float(AZURE_OPENAI_TEMPERATURE),
        max_tokens=int(AZURE_OPENAI_MAX_TOKENS),
        top_p=float(AZURE_OPENAI_TOP_P),
        stop=AZURE_OPENAI_STOP_SEQUENCE.split("|") if AZURE_OPENAI_STOP_SEQUENCE else None,
        stream=SHOULD_STREAM
    )

    if not SHOULD_STREAM:
        response_obj = {
            "id": response,
            "model": response.model,
            "created": response.created,
            "object": response.object,
            "choices": [{
                "messages": [{
                    "role": "assistant",
                    "content": response.choices[0].message.content
                }]
            }]
        }

        return jsonify(response_obj), 200
    else:
        if request.method == "POST":
            return Response(stream_without_data(response), mimetype='text/event-stream')
        else:
            return Response(None, mimetype='text/event-stream')

@app.route("/conversation", methods=["GET", "POST"])
def conversation():
    try:
        use_data = should_use_data()
        if use_data:
            return conversation_with_data(request)
        else:
            return conversation_without_data(request)
    except Exception as e:
        logging.exception("Exception in /conversation")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run()

from datetime import datetime, timedelta, timezone
import jwt
import jwt.algorithms
import streamlit as st  # all streamlit commands will be available through the "st" alias
import utils
from streamlit_feedback import streamlit_feedback

# UTC timezone setup
UTC = timezone.utc

# Init configuration
utils.retrieve_config_from_agent()
if "aws_credentials" not in st.session_state:
    st.session_state.aws_credentials = None

# Set the page title
st.set_page_config(page_title="Amazon Q Business Custom UI")

# Inject custom CSS to set the company brand image as background
st.markdown(
    """
    <style>
    /* Custom background image for the entire app */
    .stApp {
        background-image: url("https://www.consultancy.eu/illustrations/news/detail/2023-04-14-07332657-Atos_lanceert_merk_van_spin-off_Eviden_.jpg");
        background-size: cover; /* Ensures the image covers the entire background */
        background-position: center; /* Positions the image in the center */
        background-repeat: no-repeat; /* Prevents the image from repeating */
    }

    .stButton>button {
        background-color: #004aad; /* Custom company blue for buttons */
        color: white; /* White text for buttons */
        border-radius: 10px;
    }

    .stButton>button:hover {
        background-color: #003a8c; /* Darker blue on hover */
        color: white;
    }

    h1, h2, h3, h4, h5, h6 {
        color: #004aad; /* Custom blue for headings */
    }

    .stMarkdown {
        color: #333; /* Dark gray text */
    }

    .stTextArea textarea {
        background-color: #e9ecef; /* Light background for input fields */
        color: #004aad; /* Custom blue for input text */
    }

    </style>
    """,
    unsafe_allow_html=True
)

# Title for the page
st.title("Amazon Q Business Custom UI")  # Page title with custom color applied from the CSS

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""

# OAuth2 component initialization
oauth2 = utils.configure_oauth_component()
if "token" not in st.session_state:
    # If not, show authorize button
    redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    result = oauth2.authorize_button("Connect with Cognito", scope="openid", pkce="S256", redirect_uri=redirect_uri)
    if result and "token" in result:
        # If authorization successful, save token in session state
        st.session_state.token = result.get("token")
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(st.session_state.token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        st.rerun()
else:
    token = st.session_state["token"]
    refresh_token = token["refresh_token"]  # Saving the long-lived refresh_token
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]
    
    if st.button("Refresh Cognito Token"):
        # Refresh token logic
        token = oauth2.refresh_token(token, force=True)
        token["refresh_token"] = refresh_token
        st.session_state.token = token
        st.rerun()

    if "idc_jwt_token" not in st.session_state:
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
    elif st.session_state["idc_jwt_token"]["expires_at"] < datetime.now(UTC):
        # Refresh Identity Center token if expired
        try:
            st.session_state["idc_jwt_token"] = utils.refresh_iam_oidc_token(st.session_state["idc_jwt_token"]["refreshToken"])
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        except Exception as e:
            st.error(f"Error refreshing Identity Center token: {e}. Please reload the page.")

    # Layout with two columns
    col1, col2 = st.columns([1, 1])

    with col1:
        st.write("Welcome: ", user_email)

    with col2:
        st.button("Clear Chat History", on_click=clear_chat_history)

    # Initialize chat session state if not already set
    if "messages" not in st.session_state:
        st.session_state["messages"] = [{"role": "assistant", "content": "How can I help you?"}]

    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    # User input section
    if prompt := st.chat_input():
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

    # If last message is from the user, get response from backend
    if st.session_state.messages[-1]["role"] != "assistant":
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                placeholder = st.empty()
                response = utils.get_queue_chain(prompt, st.session_state["conversationId"], st.session_state["parentMessageId"], st.session_state["idc_jwt_token"]["idToken"])
                full_response = response["answer"]
                if "references" in response:
                    full_response += f"\n\n---\n{response['references']}"
                else:
                    full_response += "\n\n---\nNo sources"
                placeholder.markdown(full_response)
                st.session_state["conversationId"] = response["conversationId"]
                st.session_state["parentMessageId"] = response["parentMessageId"]

        st.session_state.messages.append({"role": "assistant", "content": full_response})

        # Collect feedback
        feedback = streamlit_feedback(feedback_type="thumbs", optional_text_label="[Optional] Please provide an explanation")

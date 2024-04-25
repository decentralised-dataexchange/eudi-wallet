import requests


def send_webhook(webhook_base_url, payload=None):
    method = "POST"
    headers = {"Content-Type": "application/json"}
    timeout = 10
    topic = "/topic/issue_credential/"
    webhook_url = webhook_base_url + topic

    try:
        # Send the request
        response = requests.request(
            method, webhook_url, json=payload, headers=headers, timeout=timeout
        )

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            print("Webhook sent successfully.")
            return True
        else:
            print(f"Failed to send webhook. Status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"An error occurred while sending the webhook: {e}")
        return False

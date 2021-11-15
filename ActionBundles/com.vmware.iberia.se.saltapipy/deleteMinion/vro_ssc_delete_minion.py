from sseapiclient import APIClient

def handler(context, inputs):
    outputs = {}
    minion_key = inputs["minionKey"]
    msg = "The address is: {0}!".format(minion_key)

    #connection info
    ssc_host = 'https://vrassc.iberia.local'
    username = 'root'
    password = '@nill0T3!'
    
    client = APIClient(ssc_host, username, password, ssl_validate_cert=False)
    client.api.minions.set_minion_key_state(state='delete', minions=[['salt',minion_key]])

    outputs["greetings"]=msg

    return outputs

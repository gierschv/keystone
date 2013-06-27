from keystone import catalog

class Default(object):    
    
    def __init__(self):
        ''' Constructor '''
        self.catalog_api = catalog.Manager()
    
    def get_directory(self):
        ''' Return services which match idp.* from the service catalog '''
        return self.format_directory(self.catalog_api.list_services({"is_admin":True}))
    
    def populate_auth_dict(self, federated, provider):
        endpoints = self.catalog_api.list_endpoints({"is_admin":True})
        service = self.catalog_api.get_service({"is_admin":True}, provider)
        for endpoint in endpoints:
            if not endpoint["interface"]=="public":
                endpoints.pop(endpoints.index(endpoint))
            elif endpoint["service_id"]==service["id"]:               
                validation = endpoint.get("validation", None)
                federated["validation"] = validation
                endpoint_url = endpoint["url"]
                federated["endpoint"] = endpoint_url
        federated["protocol"] = service["type"].split(".")[1]
    
    def format_directory(self, services):
        providers = []
        endpoints = self.catalog_api.list_endpoints({"is_admin":True})
        for service in services:
            if service["type"].startswith("idp"):
                for endpoint in endpoints:
                    if not endpoint["interface"]=="public":
                        endpoints.pop(endpoints.index(endpoint))
                    elif endpoint["service_id"]==service["id"]:
                        providers.append({"service":{"id": service["id"], "url": endpoint["url"], "name": service["name"]}})
        return {"providers": providers} 
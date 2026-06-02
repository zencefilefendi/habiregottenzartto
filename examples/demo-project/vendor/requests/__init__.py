"""
Minimal `requests` source FIXTURE for the cross-package reachability demo.

It is not the real library — it is a faithful skeleton of requests' actual call
structure so the dependency-internal analyzer can prove the path from the public
`get()` entry down to the vulnerable `rebuild_auth()` sink (CVE-2018-18074):

    get → request → Session.request → send → resolve_redirects → rebuild_auth

In production you would point `--deps-path` at the real installed package
(e.g. your venv's site-packages); this fixture makes the demo self-contained.
"""


def get(url, **kwargs):
    return request("get", url, **kwargs)


def post(url, **kwargs):
    return request("post", url, **kwargs)


def request(method, url, **kwargs):
    session = Session()
    return session.request(method, url, **kwargs)


class Session:
    def request(self, method, url, **kwargs):
        prepared = self.prepare_request(method, url)
        return self.send(prepared, **kwargs)

    def prepare_request(self, method, url):
        return {"method": method, "url": url}

    def send(self, request, **kwargs):
        response = self.transport_adapter_send(request)
        for resp in self.resolve_redirects(response, request):
            response = resp
        return response

    def transport_adapter_send(self, request):
        return {"status": 200}

    def resolve_redirects(self, resp, req, **kwargs):
        while resp.get("status") in (301, 302):
            self.rebuild_auth(req, resp)        # <-- the vulnerable sink
            yield resp

    def rebuild_auth(self, prepared_request, response):
        # CVE-2018-18074: failed to strip Authorization on cross-host redirect.
        headers = prepared_request.get("headers", {})
        return headers

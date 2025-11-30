class BaseLayer:
    def process(self, event: dict) -> dict:
        return {"layer": self.__class__.__name__, "passed": True}

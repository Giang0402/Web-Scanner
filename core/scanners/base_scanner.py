class BaseScanner:
    """Abstract base class for all scanner plugins."""

    def __init__(self, session, payloads):
        """
        Initializes the scanner plugin.
        :param session: The requests session object for making HTTP requests.
        :param payloads: A dictionary containing all loaded payloads.
        """
        self.session = session
        # Get the list of payloads corresponding to the scanner's name
        self.payloads = payloads.get(self.name, [])

    @property
    def name(self):
        """The name of the scanner, which must match the payload filename (e.g., 'xss')."""
        raise NotImplementedError("Each scanner plugin must define a 'name'.")

    def scan(self, target):
        """
        The main method to perform a scan on a target.
        :param target: A dictionary containing target information {'type': 'url'/'form', 'value': ...}.
        :return: A list of found vulnerabilities (as dictionaries).
        """
        raise NotImplementedError("Each scanner plugin must implement the 'scan' method.")
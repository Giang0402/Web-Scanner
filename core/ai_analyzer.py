import difflib
from bs4 import BeautifulSoup

class AIAnalyzer:
    """
    A redesigned analysis engine focusing on Differential Analysis 
    to detect anomalies indicative of vulnerabilities.
    """

    def __init__(self):
        # A clear list of SQL/Server error strings for quick detection.
        self.sql_error_indicators = [
            # Common SQL Errors
            "you have an error in your sql syntax", "warning: mysql",
            "unclosed quotation mark", "syntax error", "unknown column",
            "ora-00933", "invalid sql statement", "odbc driver error",
            "sql command not properly ended", "sqlite error"
        ]
        
        # A separate list for other error types
        self.file_inclusion_error_indicators = [
            "failed to open stream", "no such file or directory", "include(",
            "warning: include", "failed opening required"
        ]

    def _get_text_from_html(self, html_content):
        """Extracts clean, comparable text from HTML, removing scripts and styles."""
        if not html_content:
            return ""
        soup = BeautifulSoup(html_content, 'html.parser')
        for script_or_style in soup(["script", "style"]):
            script_or_style.decompose()
        return " ".join(soup.stripped_strings)

    def analyze_for_error_based(self, response):
        """
        Analyzes a single response to check for obvious error messages.
        This is the primary method for error-based detection.

        :param response: The HTTP response object from the server.
        :return: Tuple (is_vulnerable, evidence).
        """
        response_text = response.text.lower()
        
        # Check for classic SQL errors
        for error in self.sql_error_indicators:
            if error in response_text:
                return (True, f"Response contains a classic SQL error string: '{error}'")
        
        # Check for classic File Inclusion errors
        for error in self.file_inclusion_error_indicators:
             if error in response_text:
                return (True, f"Response contains a classic File Inclusion error string: '{error}'")

        # Check for high-impact status codes
        if response.status_code >= 500:
            return (True, f"Server returned a critical error status code: {response.status_code}")

        return (False, None)

    def compare_responses(self, response_true, response_false):
        """
        Performs a differential analysis between two responses to detect subtle changes.
        This is the core of Boolean-Based Blind detection.

        :param response_true: The HTTP response from a logically TRUE payload (e.g., ' or 1=1--).
        :param response_false: The HTTP response from a logically FALSE payload (e.g., ' and 1=2--).
        :return: Tuple (is_different, evidence).
        """
        # Rule 1: Status code difference is a strong indicator
        if response_true.status_code != response_false.status_code:
            return (True, f"Status codes differ: TRUE payload returned {response_true.status_code}, FALSE payload returned {response_false.status_code}.")

        # Rule 2: Content length difference can be a good indicator
        len_true = len(response_true.content)
        len_false = len(response_false.content)
        if abs(len_true - len_false) > 100: # Threshold for significant difference
             return (True, f"Content lengths differ significantly: {len_true} bytes vs {len_false} bytes.")

        # Rule 3: Text content difference (most reliable)
        text_true = self._get_text_from_html(response_true.text)
        text_false = self._get_text_from_html(response_false.text)
        
        if not text_true or not text_false:
            return (False, None) # Cannot compare if one is empty

        diff_ratio = difflib.SequenceMatcher(None, text_true, text_false).ratio()

        # If the pages are substantially different, it's a vulnerability.
        if diff_ratio < 0.98: # 98% similarity threshold; can be adjusted
            return (True, f"Page content differs significantly between TRUE and FALSE payloads (Similarity Ratio: {diff_ratio:.2f}). This is a strong indicator of Blind SQLi.")

        return (False, None)
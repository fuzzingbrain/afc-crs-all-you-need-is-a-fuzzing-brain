class VulnCheckPrompt:

    def __init__(self) -> None:
        pass

    def basic(
        self, catalog_text: str, top_k: int = 10
    ) -> str:
        """
        Basic vulnerability check prompt.
        """
        return f"""
        Context: you are a world-class vulnerability researcher.

        Return **JSON only**, no markdown, in this exact schema:

      {{"name":"<funcName>", "score":<1-10>, "reason":"<short>"}},
        {{"name":"<funcName>", "score":<1-10>, "reason":"<short>"}},
        ...
        ]

        Provide at most {top_k} entries, sorted by descending score.

        Reachable functions:
        {catalog_text}
        """

    def suspicious_points(
        self, function_code: str, top_k: int = 1
    ) -> str:
        return f"""
        Context: you are a world-class vulnerability researcher.

        Function code:
        {function_code}

        Return **JSON only**, no markdown, in this exact schema:

        {{"name":"<suspicious_point>", "score":<1-10>, "reason":"<short>"}},
        {{"name":"<suspicious_point>", "score":<1-10>, "reason":"<short>"}},
        ...
        ]

        Provide at most {top_k} entries, sorted by descending score.
        """


class FuzzingInputGeneratorPrompt:

    def __init__(self) -> None:
        pass

    def basic(
        self, function_code: str, suspicious_point: str
    ) -> str:
        return f"""
        Given the following function code:
        {function_code}

        And a suspicious point:
        {suspicious_point}

        Determine:

        1. How does this fuzzer function load the input data?
        2. How does this fuzzer function process the data and send into the target function?
        3. Can this suspicious point be exploited from this fuzzer harness?

        Output a python file that can generate a payload to exploit this suspicious point, named as x.bin.
        """
import json

class RPCException(Exception):
    """
    Exception class for handling RPC (Remote Procedure Call) related errors.

    This exception encapsulates information about an RPC error, including
    the original request, the response received, the underlying exception,
    and any additional information.
    """

    def __init__(self, request, response, underlying_exception, extra_info):
        """
        Initialize a new instance of the RPCException class.

        :param request: The request that caused the exception.
        :type request: Any
        :param response: The response received from the server.
        :type response: Any
        :param underlying_exception: The underlying exception that caused this exception.
        :type underlying_exception: Exception
        :param extra_info: Additional information about the exception.
        :type extra_info: Any
        """
        self.request = request
        self.response = response
        self.underlying_exception: Exception = underlying_exception
        self.extra_info = extra_info

    def __str__(self):
        """
        Return a JSON string representation of the exception object.

        :return: A JSON-formatted string containing exception details.
        :rtype: str
        """
        # Create a dictionary with exception details
        ret = {
            'request': self.request,
            'response': self.response,
            'extra_info': self.extra_info,
            'exception': None,
        }
        # Include the underlying exception if it exists
        if isinstance(self.underlying_exception, Exception):
            ret.update({'exception': str(self.underlying_exception)})
        return json.dumps(ret)

    def __repr__(self):
        """
        Return a string representation of the exception.

        This method returns the same output as __str__ for consistency.

        :return: A string representation of the exception.
        :rtype: str
        """
        return self.__str__()
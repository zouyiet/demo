<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<% String appPath = request.getContextPath(); %>
<html>
<head>
    <title>Title</title>
</head>
<body>
list
<c:forEach var="list" items="${requestScope.get('list')}" varStatus="status">
    <tr>
        <td>${list.id}</td>
        <td>${list.ip}</td>
        <td>${list.port}</td>
    </tr>
</c:forEach>
</body>
</html>

<?php
/****************************
 * FUNCTION: DISPLAY HEADER *
 ***************************/
function display_header()
{

print("<table width=\"100%\" cellpadding=\"10\">
<tr>
	<td width=\"33%\">&nbsp;</td>
	<td width=\"34%\"><h1>Sentinel+</h1></td>
	<td width=\"33%\" align=\"right\" valign=\"top\"><h5><a href=\"logout.php\">Logout</a></h5></td>
</tr>
</table>
<center>
<div id=\"menu\">
<ul>
<li><a href=\"dashboard.php\">Dashboard</a></li>
<li><a href=\"classes.php\">Vulnerability Classes</a></li>
<li><a href=\"pages.php\">Vulnerable Pages</a></li>
<li><a href=\"search.php\">Vulnerable URL Search</a></li>
<li><a href=\"configurations.php\">Configurations</a></li>
</ul>
</div>
</center>

<hr />");

}
?>

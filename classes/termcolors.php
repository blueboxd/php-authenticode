<?php

function eBold($str){return "\033[1m".$str."\033[0m";}
function eStrong($str){return "\033[2m".$str."\033[0m";}
function eUnderline($str){return "\033[4m".$str."\033[0m";}
function eBlink($str){return "\033[5m".$str."\033[0m";}
function eInverted($str){return "\033[7m".$str."\033[0m";}

function eBlack($str){return "\033[30m".$str."\033[0m";}
function eRed($str){return "\033[31m".$str."\033[0m";}
function eGreen($str){return "\033[32m".$str."\033[0m";}
function eYellow($str){return "\033[33m".$str."\033[0m";}
function eBlue($str){return "\033[34m".$str."\033[0m";}
function ePurple($str){return "\033[35m".$str."\033[0m";}
function eCyan($str){return "\033[36m".$str."\033[0m";}
function eGray($str){return "\033[37m".$str."\033[0m";}

function eBlackFilled($str){return "\033[40m".$str."\033[0m";}
function eRedFilled($str){return "\033[41m".$str."\033[0m";}
function eGreenFilled($str){return "\033[42m".$str."\033[0m";}
function eYellowFilled($str){return "\033[43m".$str."\033[0m";}
function eBlueFilled($str){return "\033[44m".$str."\033[0m";}
function ePurpleFilled($str){return "\033[45m".$str."\033[0m";}
function eCyanFilled($str){return "\033[46m".$str."\033[0m";}
function eGrayFilled($str){return "\033[47m".$str."\033[0m";}

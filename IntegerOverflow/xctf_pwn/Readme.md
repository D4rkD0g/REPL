```c
read(0, &buf, 0x199u);
return check_passwd(&buf);
```
程序可以读入0x199个数据，传给check_passwd

```c
char *__cdecl check_passwd(char *s)
{
  char *result; // eax
  char dest; // [esp+4h] [ebp-14h]
  unsigned __int8 v3; // [esp+Fh] [ebp-9h]

  v3 = strlen(s);
  if ( v3 <= 3u || v3 > 8u )
  {
    puts("Invalid Password");
    result = (char *)fflush(stdout);
  }
  else
  {
    puts("Success");
    fflush(stdout);
    result = strcpy(&dest, s);
  }
  return result;
}
```

获得输入的长度，此时注意长度保存在一个8位的空间中，所以最多表示255，因此有整数溢出  
后续strcpy时可以缓冲区溢出  
---
layout: post
title: OS X에 burp suite 설치하기
tags: Web

---

맥에서 컴퓨터 패킷 잡기 위해서 burp suite를 깔아보았다.

원래 맨날 피들러 썼어서 사실 ctf할 때도 패킷 잡을 일 있으면 윈도우 vm을 키고 피들러를 켜서 잡았는데 이제 불필요한 노동을 줄이고자 버프 슈트를 사용해보려고 설치하게 됐다.

1. 버프슈트 맥용을 다운받고 설치한다. [link](https://portswigger.net/burp/communitydownload){:target="_blank"}
2. 버프슈트를 실행한 후 [`http://localhost:8080/cert`](http://localhost:8080/cert){:target="_blank"}를 접속하면 인증서가 다운로드 된다. 그걸 더블클릭해서 keychain에 등록한다.
3. 키체인에서 Certificates - PortSwigger CA를 Get Info한 뒤에 Trust 탭에서 Always Trust를 한다.
4. 그럼 이제 https 패킷도 잡을 수가 있다. 근데 unknown host 에러가 뜬다면 네트워크에 dns 설정을 들어가서 8.8.8.8을 추가해준다.
5. 끝

사용할 때는 네트워크에 proxies 탭을 들어가서 Web Proxy와 Secure Web Proxy를 127.0.0.1 8080으로 프록시 설정하고 OK - Apply 하면 패킷을 잡을 수 있다.

처음에 쪼끔 헤멧어서 정리글을 남긴다,,, 암튼 이제 피들러 쓸라고 윈도우 킬 일 없따
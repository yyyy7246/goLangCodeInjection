# goLangCodeInjection

##### 설명

1. 관리자 권한으로 실행시 powershell에서 C드라이브를 탐지 예외 폴더로 지정
2. msfvenom에서 리버스 쉘 코드를 바이너리로 생성후 Base64로 인코딩하여 문자열로 저장
3. 저장한 문자열을 실행중인 프로세스의 pid를 입력하면 해당 프로세스에 주입
4. 이후 코드를 난독화하였음.

난독화 이후 윈도우 디펜더에선 탐지가 안되었으며 바이러스 토탈에는 64개 중 5개만 탐지 되었음.

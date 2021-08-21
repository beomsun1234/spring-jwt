## spring-boot jwt를 이용한 로그인 구현


#### 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있다

 - /login을 요청해서 username, password 전송하면(post) UsernamePasswordAuthenticationFilter가 동작함(나의 프로젝트는 formlogin을 disable했기에 위에 필터가 작동하지 않는다)
   
 
   1. UsernamePasswordAuthenticationFilter를 작동시키기 위해서는 (JwtAuthenticationFilter)를 시큐리티필터에 등록해줘야한다.
        
   2. 등록 후 /login 요청을 하면 로그인 시도를 위해 UsernamePasswordAuthenticationFilter의 <strong>attemptAuthentication</strong> 함수가 실행된다.
          이후 username(email), password를 받아서 정상인지 로그인 시도를 해본다. 
        
   3. authenticationManager로 로그인 시도를 하면 CustomUserDetailsService의 loadUserByUsername 함수가 실행된다.
        
   4. authentication 객체가 sesstion 영역에 저장된다(로그인이 되었다는뜻). 이후 authentication객체를 리턴해주면 된다.(권환관리를 시큐리티가 대신 해주기때문에)
          굳이 jwt토큰을 사용하면서 세션을 만들 이유가 없다. 이유는 권한 처리떄문에 세션에 넣어준다.
          
         
         public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
             private final AuthenticationManager authenticationManager;
             //@Value("${jwttest.secret-key}")
             private String secret = "qkrqjatjs12345678910111231231232131232131231231231231231232131231231231245";
             /**
              * /login 요청오면 실행되는 함수
              */
             @Override
             public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
                 log.info("로그인시도중");
                 /**
                  * 1.useremail, password 받아서
                  * 2.정상인지 로그인시도 해봄. authenticationManager로 로그인시도를 하면 CustomUserDetailsService가 호출된다
                  * 3. securityUser를 세션에 담고
                  * 4. jwt 토큰을 만들어 응답
                  */
                 //1
                 try {
                     ObjectMapper objectMapper = new ObjectMapper();
                     User user = objectMapper.readValue(request.getInputStream(), User.class);
                     log.info("username={}", user.getName());
                     log.info("email={}", user.getEmail());
                     log.info("pass={}", user.getPassword());           
                     
                     UsernamePasswordAuthenticationToken newAuthentication = new UsernamePasswordAuthenticationToken(
                             user, user.getPassword());
                     UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword());
                     //  CustomUserDetailsService의 loadByUsername() 함수가 실행된다(나는 email로 호출한다)
                     Authentication authentication = authenticationManager.authenticate(authenticationToken);
                     // authentication 객체가 세션영역에 저장됨 => 로그인이 되었다는 뜻
                     SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
         
                     log.info("-----------로그인완료됨");
                     log.info("email={}", securityUser.getEmail());
                     return authentication;
         
                 } catch (IOException e) {
                     e.printStackTrace();
                 }
                 return null;
             }
          
          
 (로그인완료 후)<br>
            
 1. attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
 2. JWT 토큰을 만들어서 request요청한 사용자에게 jwt토큰을 response해주면된다
 
        
        @Override
           protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
               log.info("인증이완료되었습니다---- 토큰발급");
       
               SecurityUser user = (SecurityUser)authResult.getPrincipal();
               log.info("screct={}",secret);
               String jwtToken = Jwts.builder().setSubject("cos_token")
                       .setExpiration(new Date(System.currentTimeMillis()+(60000*10)))
                       .claim("id",user.getUser().getId())
                       .claim("email", user.getEmail())
                       .claim("name", user.getUsername())
                       .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                       .compact();
               response.addHeader("Authorization", "Bearer "+jwtToken);
           }
           
           
  ------
  
#### 유저네임or email, 패스워드 로그인 정상
   - 서버쪽 - JWT토큰 생성 후 클라이언트쪽으로 JWT토큰 응답
   - 클라이언트쪽 - JWT토큰을 가지고 요청 
   - 서버는 JWT토큰이 유효한지를 판단(필터를 만들어야한다)
        
        

#### 시큐리티가 filter가지고 있는데 그 필터중에 BasicAuthenticatrionFilter라는 것이 있다.
  - 권한이나 인증이 필요한 특정 주소를 요청했을 위 필터를 무조건 타게되어있다
  - 만약 권한이나 인증이 필요한 주소가 아니라면 필터를 안탄다
  
  
       //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게된다
       
       @Override
          protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
              String jwtHeader = request.getHeader("Authorization");
              // 헤더가 있는지 확인
              if( jwtHeader == null || !jwtHeader.startsWith("Bearer")){
                  chain.doFilter(request,response);
                  log.info("헤더가 없으면 필터 안타고 리턴");
                  return;
              }
              String jwtToken = jwtHeader.substring(7);
              Claims claims = Jwts.parserBuilder()
                      .setSigningKey(secret.getBytes())
                      .build()
                      .parseClaimsJws(jwtToken)
                      .getBody();
              if (claims.get("email",String.class) !=null){
                  log.info("토큰검증 통과");
                  User user = userRepository.findByEmail(claims.get("email", String.class)).orElseThrow(()->new IllegalArgumentException("찾는 이메일이 없습니다."));
                  SecurityUser securityUser = new SecurityUser(user);
                  //jwt토큰 서명을 통해 서명이 정상이면 Authentication객체를만들어준다
                  Authentication authentication = new UsernamePasswordAuthenticationToken(securityUser,null,securityUser.getAuthorities());
                  //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
                  SecurityContextHolder.getContext().setAuthentication(authentication);
                  chain.doFilter(request,response);
              }
          }


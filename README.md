## spring-boot jwt를 이용한 로그인 구현
마이크로서비스를 위한 인증과 인가

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



-------
## 리팩토링

Jwt 토큰 발행 및 검증


    public class JwtUtil {
        public final static long TOKEN_VALIDATION_SECOND = 1000L * 10;
        public final static long REFRESH_TOKEN_VALIDATION_SECOND = 1000L * 60 * 24 * 2;
        private String secret= "qkrqjatjs12345678910111231231232131232131231231231231231232131231231231245";
    
    
        /**
         * String access_token = Jwts.builder().setSubject("cos_token")
         *             .setExpiration(new Date(System.currentTimeMillis()+(60000*10)))
         *             .claim("id",userInfo.getId())
         *             .claim("email", userInfo.getEmail())
         *             .claim("name", userInfo.getName())
         *             .signWith(SignatureAlgorithm.HS256, secret.getBytes())
         *             .compact();
         */
    
        /**
         * 토큰이 유효한 토큰인지 검사한 후, 토큰에 담긴 Payload 값을 가져온다.
         */
        public Claims extractAllClaims(String token) throws ExpiredJwtException {
            return Jwts.parserBuilder()
                    .setSigningKey(secret.getBytes())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        }
    
        /**
         * if (claims.get("email",String.class) !=null){
         *             log.info("토큰검증 통과");
         *             User user = userRepository.findByEmail(claims.get("email", String.class)).orElseThrow(()->new IllegalArgumentException("찾는 이메일이 없습니다."));
         *             SecurityUser securityUser = new SecurityUser(user);
         *             //jwt토큰 서명을 통해 서명이 정상이면 Authentication객체를만들어준다
         *             Authentication authentication = new UsernamePasswordAuthenticationToken(securityUser,null,securityUser.getAuthorities());
         *             //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
         *             SecurityContextHolder.getContext().setAuthentication(authentication);
         *             chain.doFilter(request,response);
         * @param token
         * @return
         */
        public String getEmail(String token) {
            return extractAllClaims(token).get("email", String.class);
        }
    
        /*
        isTokenExpired() : 토큰이 만료됐는지 안됐는지 확인.
         */
        public Boolean isTokenExpired(String token) {
            final Date expiration = extractAllClaims(token).getExpiration();
            return expiration.before(new Date());
        }
    
        public String generateToken(UserInfoDto user) {
            return doGenerateToken(user, TOKEN_VALIDATION_SECOND);
        }
    
        /**
         * 토큰을 생성, 페이로드에 담길 값은 userInfo
         * @param userInfoDto
         * @param expireTime
         * @return
         */
        private String doGenerateToken(UserInfoDto userInfoDto, long expireTime) {
    
            Claims claims = Jwts.claims();
            claims.put("email", userInfoDto.getEmail());
            claims.put("id", userInfoDto.getId());
            claims.put("name", userInfoDto.getName());
    
            String jwt = Jwts.builder()
                    .setHeaderParam("typ", "JWT")
                    .setClaims(claims)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + expireTime))
                    .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                    .compact();
    
            return jwt;
        }
    
        public String generateRefreshToken(UserInfoDto user) {
            return doGenerateToken(user, REFRESH_TOKEN_VALIDATION_SECOND);
        }
    
        public Boolean validateToken(String token, SecurityUser user) {
            final String emial = getEmail(token);
            return (user.equals(user.getUsername()) && !isTokenExpired(token));
        }
    
        public TokenDto tokenToDto(String accessToken, String refreshToken){
            return TokenDto.builder().access_token(accessToken).refresh_token(refreshToken).build();
        }
    
        public String extractHeader(String headerJwt){
            return headerJwt.substring(7);
        }



--------
인증 부분


    @Slf4j
    public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
        private final AuthenticationManager authenticationManager;
        private final ObjectMapper objectMapper;
        private final JwtUtil jwtUtil;
        public JwtAuthenticationFilter(AuthenticationManager authenticationManager,ObjectMapper objectMapper, JwtUtil jwtUtil){
            this.authenticationManager = authenticationManager;
            this.objectMapper = objectMapper;
            this.jwtUtil =  jwtUtil;
        }
        //@Value("${jwttest.secret-key}")
        private String secret= "qkrqjatjs12345678910111231231232131232131231231231231231232131231231231245";
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
                LoginForm loginUser = objectMapper.readValue(request.getInputStream(), LoginForm.class);
                log.info("email={}", loginUser.getEmail());
                log.info("pass={}", loginUser.getPassword());
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginUser.getEmail(), loginUser.getPassword());
                //  CustomUserDetailsService의 loadByUsername() 함수가 실행된다(나는 email로 호출한다)
                Authentication authentication = authenticationManager.authenticate(authenticationToken);
                // authentication 객체가 세션영역에 저장됨 => 로그인이 되었다는 뜻
                //SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
                log.info("-----------로그인완료됨");
                //log.info("email={}", securityUser.getEmail());
                return authentication;
    
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
        // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다
        // jwt 토큰으 ㄹ만들어서 request요청한 사용자에게 jwt토큰을 reponse해주면된다
        @Override
        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
            log.info("인증이완료되었습니다---");
            SecurityUser user = (SecurityUser)authResult.getPrincipal();
            UserInfoDto userInfo = UserInfoDto.builder()
                    .id(user.getUser().getId())
                    .name(user.getUsername())
                    .email(user.getEmail())
                    .role(user.getUser().getRole())
                    .build();
            log.info(" ----토큰발급-------");
            String access_token =jwtUtil.generateToken(userInfo);
            String refresh_token = jwtUtil.generateRefreshToken(userInfo);
    
            response.addHeader("Authorization", "Bearer "+access_token);
            response.addHeader("refreshToken ", "Bearer "+refresh_token);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
    
            PrintWriter printWriter = response.getWriter();
            printWriter.print(objectMapper.writeValueAsString(jwtUtil.tokenToDto(access_token,refresh_token)));
            printWriter.flush();
    
        }
        /**
         * 이메일 ,패스워드 로그인 정상
         * 서버쪽 세션 ID 생성
         * 클라이언트 쿠키로 세션 ID를 응답
         * 요청할 때마다 쿠키값 세션ID를 항상 들고 서버쪽으로 요청하기 때문에
         * 서버는 세션ID가 유요한지 판다해서 유요하면 인증이 필요한 페이지로 접근하게 하면된다,
         *
         * 1.이메일, 패스워드 로그인정상
         * 2. jwt토큰생성
         * 3. 클라이언트 쪽으로 JWT 토큰 응답
         * 4. 요청할때마다 jwt토큰을 가지고 요청
         * 5. 서버는 JWT토큰이 유효한지를 판단
         */
    }


--------
인가

// 시큐리티가 filter가지고 있는데 그 필터중에 BasicAuthenticatrionFilter라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 위 필터를 무조건 타게되어있다
// 만약 권한이나 인증이 필요한 주소가 아니라면 필터를 안탄다
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    //@Value("${jwt.secret-key}")
    private String secret="qkrqjatjs12345678910111231231232131232131231231231231231232131231231231245";
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository,JwtUtil jwtUtil) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 시큐리티가 filter가지고 있는데 그 필터중에 BasicAuthenticatrionFilter라는 것이 있다.
     * 권한이나 인증이 필요한 특정 주소를 요청했을 위 필터를 무조건 타게되어있다
     * 만약 권한이나 인증이 필요한 주소가 아니라면 필터를 안탄다
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String jwtHeader = request.getHeader("Authorization");
        String header = request.getHeader("refreshToken"); //
        log.info("header={}",header);
        String refreshToken =null;
        // 헤더가 있는지 확인
        if( jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request,response);
            log.info("헤더에 jwt토큰 없음");
            return;
        }
        try {
            String jwtToken = jwtUtil.extractHeader(jwtHeader);
            String email = jwtUtil.getEmail(jwtToken);
            if (email != null){
                log.info("토큰검증 통과");
                User user = userRepository.findByEmail(email).orElseThrow(()->new IllegalArgumentException("찾는 이메일이 없습니다."));
                SecurityUser securityUser = new SecurityUser(user);
                if (jwtUtil.validateToken(jwtToken,securityUser)){
                    //jwt토큰 서명을 통해 서명이 정상이면 Authentication객체를만들어준다
                    log.info("유요한토큰입니다");
                    Authentication authentication = new UsernamePasswordAuthenticationToken(securityUser,null,securityUser.getAuthorities());
                    //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }catch (ExpiredJwtException e){
            log.info("토큰유효기간만료됨");
            if(header!=null){
                refreshToken = header.substring(7);
                log.info("refreshToken={}",refreshToken);
            }
        } catch (Exception e){
        }
        try{
            if(refreshToken != null){
                String email = jwtUtil.getEmail(refreshToken);
                log.info("email={}",email);
                if(email.equals(jwtUtil.getEmail(refreshToken))){
                    User user = userRepository.findByEmail(email).orElseThrow(()->new IllegalArgumentException("찾는 이메일이 없습니다."));
                    SecurityUser securityUser = new SecurityUser(user);
                    Authentication authentication = new UsernamePasswordAuthenticationToken(securityUser,null,securityUser.getAuthorities());
                    //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
                    UserInfoDto userInfo = UserInfoDto.builder()
                            .id(securityUser.getUser().getId())
                            .name(securityUser.getUsername())
                            .email(securityUser.getEmail())
                            .role(securityUser.getUser().getRole())
                            .build();
                    
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    String newToken =jwtUtil.generateToken(userInfo);
                }
            }
        }catch(ExpiredJwtException e){

        }
        chain.doFilter(request,response);
    }
}


1. 현재 로그인 한 사용자 헤더에 access token과 refresh token을 가지고 있다.(쿠키에 저장하도록 바꿔야함)
2. Access Token이 유효하면 AccessToken내 payload를 읽어 사용자와 관련있는 securityUser를 생성
3. Access Token이 유효하지 않으면 Refresh Token값을 읽어드림.
4. Refresh Token을 읽어 Access Token을 사용자에게 재생성하고, 요청을 허가시킴.

- Access Token탈취의 위험이 존재하기 때문에 짧은 유효시간을 두어, Access Token이 탈취 당하더라도 만료되어 사용할 수 없도록 한다.

- Refresh Token은 서버에서 그 값(Redis)을 저장함. Refresh Token을 사용할 상황이 오면 반드시 서버에서 그 유효성을 판별, 유효하지 않는 경우라면 요청을 거부. 혹은 사용자로부터 탈취 됐다라는 정보가 오면 그 Refrsh Token을 폐기할 수 있도록 설정.(나중에 할것)



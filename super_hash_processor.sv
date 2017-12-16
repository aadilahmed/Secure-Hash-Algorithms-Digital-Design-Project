module super_hash_processor(input logic clk, reset_n, start,
                            input logic [1:0] opcode,
                            input logic [31:0] message_addr, size, output_addr,
                            output logic done, mem_clk, mem_we,
                            output logic [15:0] mem_addr,
                            output logic [31:0] mem_write_data,
                            input logic [31:0] mem_read_data);
									 
									 
  enum logic [3:0] {IDLE = 4'b0000, INITIAL = 4'b0001, READ = 4'b0010, 
                   PAD1=4'b0011,PAD2 = 4'b0100, PROLOG=4'b0101, KERNEL=4'b0110,
						 EPILOG = 4'b0111, POST=4'b1000, DONE = 4'b1001, WAIT=4'b1010, 
						 READ2=4'b1011} state; 
	
  function logic [15:0] num_blocks(input logic [31:0] size);	
    if ((size << 3) % 512 <= 447)
      num_blocks = ((size << 3)/512) + 1;
    else
      num_blocks = ((size << 3)/512) + 2;
  endfunction
  
  function logic [31:0] rotateR(input logic [31:0] x,input logic [7:0] r);
    begin
      rotateR = (x >> r) | (x << (32-r));
    end
  endfunction
  
  function logic [31:0] rotateL(input logic [31:0] x,input logic [7:0] l);
    begin
      rotateL = (x << l ) | (x >> (32-l));
    end
  endfunction
  
  
  //-------------------------SHA1 functions----------------------------------// 
  // SHA1 f
  function logic [31:0] sha1_f(input logic [7:0] t, input logic [31:0] b,
                               input logic [31:0] c,input logic [31:0] d);
    begin
     if (t <= 19)
         sha1_f = (b & c) | ((~b) & d);
     else if (t <= 39)
         sha1_f = b ^ c ^ d;
     else if (t <= 59)
         sha1_f = (b & c) | (b & d) | (c & d);
     else
         sha1_f = b ^ c ^ d;
    end
  endfunction
  
  // SHA1 k
  function logic [31:0] sha1_k(input logic [7:0] t);
    begin
     if (t <= 19)
         sha1_k = 32'h5a827999;
     else if (t <= 39)
         sha1_k = 32'h6ed9eba1;
     else if (t <= 59)
         sha1_k = 32'h8f1bbcdc;
     else
         sha1_k = 32'hca62c1d6;
    end
  endfunction
  
  //-------------------------SHA1 function end-------------------------------//
  
  //-------------------------MD5 functions-----------------------------------//
  
  // MD5 S constants
  parameter byte S[0:15] = '{
   8'd7, 8'd12, 8'd17, 8'd22,
   8'd5, 8'd9, 8'd14, 8'd20,
   8'd4, 8'd11, 8'd16, 8'd23,
   8'd6, 8'd10, 8'd15, 8'd21
  };
  
  //MD5 S
  function logic [31:0] get_S(input logic [5:0] t);
   logic [3:0] i;
   i = {t[5:4], t[1:0]};
   get_S = S[i];
  endfunction
  
	// MD5 K constants
	parameter int md5_k[0:63] = '{
		 32'hd76aa478, 32'he8c7b756, 32'h242070db, 32'hc1bdceee,
		 32'hf57c0faf, 32'h4787c62a, 32'ha8304613, 32'hfd469501,
		 32'h698098d8, 32'h8b44f7af, 32'hffff5bb1, 32'h895cd7be,
		 32'h6b901122, 32'hfd987193, 32'ha679438e, 32'h49b40821,
		 32'hf61e2562, 32'hc040b340, 32'h265e5a51, 32'he9b6c7aa,
		 32'hd62f105d, 32'h02441453, 32'hd8a1e681, 32'he7d3fbc8,
		 32'h21e1cde6, 32'hc33707d6, 32'hf4d50d87, 32'h455a14ed,
		 32'ha9e3e905, 32'hfcefa3f8, 32'h676f02d9, 32'h8d2a4c8a,
		 32'hfffa3942, 32'h8771f681, 32'h6d9d6122, 32'hfde5380c,
		 32'ha4beea44, 32'h4bdecfa9, 32'hf6bb4b60, 32'hbebfbc70,
		 32'h289b7ec6, 32'heaa127fa, 32'hd4ef3085, 32'h04881d05,
		 32'hd9d4d039, 32'he6db99e5, 32'h1fa27cf8, 32'hc4ac5665,
		 32'hf4292244, 32'h432aff97, 32'hab9423a7, 32'hfc93a039,
		 32'h655b59c3, 32'h8f0ccc92, 32'hffeff47d, 32'h85845dd1,
		 32'h6fa87e4f, 32'hfe2ce6e0, 32'ha3014314, 32'h4e0811a1,
		 32'hf7537e82, 32'hbd3af235, 32'h2ad7d2bb, 32'heb86d391
	};
	
	// MD5 g
  function logic[3:0] md5_g(input logic [7:0] t);
  begin
     if (t <= 15)
       md5_g = t;
     else if (t <= 31)
       md5_g = (5*t + 1) % 16;
     else if (t <= 47)
       md5_g = (3*t + 5) % 16;
     else
       md5_g = (7*t) % 16;
  end
  endfunction
  
  // MD5 f
	function logic[31:0] md5_f(input logic [31:0] b,c,d, input logic [7:0] t);
	begin
		 if (t <= 15)
			  md5_f = (b & c) | ((~b) & d);
		 else if (t <= 31)
			  md5_f = (d & b) | ((~d) & c);
		 else if (t <= 47)
			  md5_f = b ^ c ^ d;
		 else
			  md5_f = c ^ (b | (~d));
	end
	endfunction
	  
	  
	//MD5 op  
	function logic[127:0] md5_op(input logic [31:0] a, b, c, d, w,f,k,s,
										  input logic [7:0] t);
		 logic [31:0] t1, t2; // internal signals
	begin
		 t1 = a + f+ k + w;
		 t2 = b + ((t1 << s)|(t1 >> (32-s)));
		 md5_op = {d, t2, b, c};
	end
	endfunction
	
	//--------------------------MD5 functions end-----------------------------//
	
	//--------------------------SHA256 functions------------------------------//
	
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,k,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
    begin
    S1 = rotateR(e, 6) ^ rotateR(e, 11) ^ rotateR(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k + w;
    S0 = rotateR(a, 2) ^ rotateR(a, 13) ^ rotateR(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;

    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
    end
   endfunction

  // SHA256 K constants
  parameter int sha256_k[0:63] = '{
   32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
   32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
   32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
   32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
   32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
   32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
   32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
   32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
  };
  
  //---------------------------SHA256 funcitons end--------------------------//
  
  logic   [31:0] h0;
  logic   [31:0] h1;
  logic   [31:0] h2;
  logic   [31:0] h3;
  logic   [31:0] h4;
  logic   [31:0] h5;
  logic   [31:0] h6;
  logic   [31:0] h7;
  
  logic padded;
  logic [7:0] blocks,count;
  logic [31:0] w[0:15];
  //logic [15:0] j;//,pad_len;
  
  logic [31:0] a,b,c,d,e,f,g,h,Wt;					
  logic [7:0] t,m,i;
					
  // SHA1				
  logic [31:0] K,F,T,G;  
  
  //MD5
  logic [31:0] f_md5,k_md5,s_md5;
  logic [7:0] g_md5;
  
  //SHA 256
  logic [31:0] temp1,temp2;
  
  assign mem_clk = clk;
  assign blocks = num_blocks(size);
  
  
  always_ff @(posedge clk, negedge reset_n)
  begin
    if (!reset_n) begin
      done <= 0;
      count <= 1;
		state <= IDLE;
    end else begin
      case (state)
		
        IDLE:
		  	   if (start) begin
				  case (opcode)
               2'b00: begin // md5
                 h0 = 32'h67452301;
			        h1 = 32'hEFCDAB89;
					  h2 = 32'h98BADCFE;
					  h3 = 32'h10325476;
					  h4 = 32'h00000000;
					  h5 = 32'h00000000;
					  h6 = 32'h00000000;
					  h7 = 32'h00000000;
					end
				 2'b01: begin // sha1
					  h0 = 32'h67452301;
					  h1 = 32'hEFCDAB89;
					  h2 = 32'h98BADCFE;
					  h3 = 32'h10325476;
					  h4 = 32'hC3D2E1F0;
					  h5 = 32'h00000000;
					  h6 = 32'h00000000;
					  h7 = 32'h00000000;
					end
				 2'b10: begin // sha256
					  h0 = 32'h6a09e667;
					  h1 = 32'hbb67ae85;
					  h2 = 32'h3c6ef372;
					  h3 = 32'ha54ff53a;
					  h4 = 32'h510e527f;
					  h5 = 32'h9b05688c;
					  h6 = 32'h1f83d9ab;
					  h7 = 32'h5be0cd19;
					end
				 endcase

				mem_addr <= message_addr;
            mem_we <= 0;
            //j <= 0;
				padded <= 0;
				state <= INITIAL;
				end
				
		  INITIAL: begin
		     case(opcode)
			    2'b00: begin
		         a <= h0;
				   b <= h1;
				   c <= h2;
				   d <= h3;
				 end
				 2'b01: begin
				   a <= h0;
				   b <= h1;
				   c <= h2;
				   d <= h3;
				   e <= h4;
			    end
				 2'b10: begin
				   a <= h0;
				   b <= h1;
				   c <= h2;
				   d <= h3;
				   e <= h4;
					f <= h5;
					g <= h6;
					h <= h7;
				 end
			  endcase
			  
				 i <= 0;
				 t <= 0;
				 mem_addr <= mem_addr +1;
		       state <= READ;    
				 end
	 
	     READ: begin
		          if (mem_addr == output_addr +1) begin
						w[0] <= 32'h80000000;
						i <= i+1;
						state <= PAD2;
					 end else
		          if (mem_addr == output_addr) begin		
                  if (padded ==0) begin
						  w[i] <= mem_read_data;
						  mem_addr <= mem_addr -1;
                    state <= WAIT;
						end 
                  else begin						
						  Wt <= 32'h00000000;
		              state <= PAD2;
						end
					end
		          else begin
		              w[i] <= mem_read_data;
		              i <= i + 1;
		              //j <= j + 1;
		              mem_addr <= mem_addr +1;
		              state <= READ2;
		          end
		        end
				  
		 READ2: begin
		         Wt <= w[t];
		         if (mem_addr == output_addr) begin
					  w[i] <= mem_read_data;
					  //Wt <
		           mem_addr <= mem_addr - 1;
		           state <= WAIT;
		         end
					else begin
		           w[i] <= mem_read_data;
		           i <= i + 1;
		           //j <= j + 1;
		           mem_addr <= mem_addr +1;
		           //Wt <= w[t];
					  state <= KERNEL;
					end
					end
					
			WAIT: begin
		         if (i == 0)
					  Wt <= w[t];
		  	      if (size % 4 == 0) begin      
		            i <= i+1;
		            //j <= j+1;
		            state <= PAD1;
		          end
		          else
		            state <= PAD1;
				end
				
		  PAD1: begin
		          case (size % 4)
                  0: w[i] <= 32'h80000000; 
                  1: w[i] <= (mem_read_data & 32'hFF000000) | 32'h00800000;
                  2: w[i] <= (mem_read_data & 32'hFFff0000) | 32'h00008000;
                  3: w[i] <= (mem_read_data & 32'hFFFFFF00) | 32'h00000080;
                  endcase
						if (i == 16) begin
						  padded <= 0;
						  mem_addr <= mem_addr +1;
						  state <= KERNEL;
						end
						else begin
						  padded <=1;
                    i <= i + 1;
                    //j <= j + 1;
						  mem_addr <= mem_addr +1;
                    state <= PAD2;
						end
				end
				
		  PAD2: begin
		             if (i==1)
						   Wt <= w[0];
		             for(m=0;m<16;m=m+1) begin
						   if (m>=i)
						     w[m] <= 32'h00000000;
						 end
						 if (count == blocks) begin
						   w[14] <= size >> 29;
		               w[15] <= size*8;
						 end
						 //Wt <= w[t];
						 i <= 16;
		             state <= KERNEL;
				  end
	 
	     KERNEL: begin
		     case(opcode)
			    2'b01: begin
			    if (t < 80 ) begin
			         T <= Wt + sha1_k(t) + e;
					   F <= sha1_f(t,b,c,d);
					   e <= d;
					   d <= c;
					   c <= rotateL(b,30);
					   if ( t == 0 )
						  b <= a;
						else
						  b <= rotateL(b,5) + T + F;
					   t <= t+1;
					   state <= KERNEL;
						
			      if ( i<16) begin
						  w[i] <= mem_read_data;
						  if (mem_addr == output_addr && (i < 15 || size%4 !=0)) begin
		                mem_addr <= mem_addr - 1;
		                state <= WAIT;
		              end	
						  else begin 
		              i <= i + 1;
		              //j <= j + 1;
		              mem_addr <= mem_addr +1;	
						  end
				    end
					 if (t > 14) begin
                  Wt <= rotateL(G,1);//rotateL(w[13]^w[8]^w[2]^w[0],1);
						//Wt <= rotateL(w[13]^w[8]^w[2]^w[0],1);
						  for(m=0;m<15;m=m+1) begin
						    w[m] <= w[m+1];
						  end
						w[15] <= rotateL(G,1);
						//w[15] <= rotateL(w[13]^w[8]^w[2]^w[0],1);
						G <= w[14]^w[9]^w[3]^w[1];
					 end 
					 else if (t == 14 ) begin
					   G <= w[13]^w[8]^w[2]^w[0];
						Wt <= w[t+1];
					 end
					 else begin
					   Wt <= w[t+1]; 
					 end
				  end else
					 state <= POST;
				end
				
				2'b00: begin
				  if (t < 64) begin
					 {a, b, c, d}<=md5_op(a, b, c, d, Wt,md5_f(b,c,d,t),md5_k[t],get_S(t),t);
					 g_md5 <= md5_g(t+2);
					 t <= t+1; 	 			
					 state <= KERNEL;
					 if (t <15) begin
					   Wt <= w[t+1];
					   if ( i<16) begin
						  w[i] <= mem_read_data;
						  if (mem_addr == output_addr && (i < 15 || size%4 !=0)) begin
		                mem_addr <= mem_addr - 1;
							 //if (i == 15)
							   //state <= PAD1;
							 //else
		                  state <= WAIT;
		              end	
						  else begin 
						  //Wt <= w[t+1];
		              i <= i + 1;
		              //j <= j + 1;
		              mem_addr <= mem_addr +1;	
						  end
				      end
					 end
					 else begin
                  Wt <= w[g_md5];				
					 end 
				  end else
					 state <= POST;
			  end
			  
			  2'b10: begin
			  if (t < 64) begin
					 {a, b, c, d,e, f, g, h}<=sha256_op(a, b, c, d, e, f, g, h, Wt,sha256_k[t],t);
					 t <= t+1;
                state <= KERNEL;
					 if ( i<16) begin
						  w[i] <= mem_read_data;
						  if (mem_addr == output_addr && (i < 15 || size%4 !=0)) begin
		                mem_addr <= mem_addr - 1;
							 //if (i == 15)
							   //state <= PAD1;
							 //else
		                  state <= WAIT;
		              end	
						  else begin 
						  //Wt <= w[t+1];
		              i <= i + 1;
		              //j <= j + 1;
		              mem_addr <= mem_addr +1;	
						  end
				    end
					 if (t > 14) begin
//                  Wt <= w[0] + (rotateR(w[1],7)^rotateR(w[1],18)^(w[1] >> 3)) + w[9] 
//						+ (rotateR(w[14],17)^rotateR(w[14],19)^(w[14]>>10));
                    Wt <= w[0] + temp1 + w[9] + temp2;
						  for(m=0;m<15;m=m+1) begin
						    w[m] <= w[m+1];
						  end
//						w[15] <= w[0] + (rotateR(w[1],7)^rotateR(w[1],18)^(w[1] >> 3)) + w[9] 
//						+ (rotateR(w[14],17)^rotateR(w[14],19)^(w[14]>>10));
                  w[15] <= w[0] + temp1 + w[9] + temp2;
						temp1 <= rotateR(w[2],7)^rotateR(w[2],18)^(w[2] >> 3);
						temp2 <= rotateR(w[15],17)^rotateR(w[15],19)^(w[15]>>10);
					 end 
					 else if (t == 14) begin
					   temp1 <= rotateR(w[1],7)^rotateR(w[1],18)^(w[1] >> 3);
						temp2 <= rotateR(w[14],17)^rotateR(w[14],19)^(w[14]>>10);
						Wt <= w[t+1];
					 end
					 else begin
					   Wt <= w[t+1];
					 //state <= KERNEL; 
					 end
			  end else
				 state <= POST;
			  end
			  
			  
			endcase
			end
				
		  POST: begin
		        case(opcode)
				    2'b00: begin
					  h0 <= h0 + a;
				     h1 <= h1 + b;
				     h2 <= h2 + c;
				     h3 <= h3 + d;
				    end
					 
				    2'b01: begin
			        h0 <= h0 + rotateL(b,5) + T + F;
				     h1 <= h1 + b;
				     h2 <= h2 + c;
				     h3 <= h3 + d;
				     h4 <= h4 + e;
					  end
					 
					 default: begin
					  h0 <= h0 + a;
				     h1 <= h1 + b;
				     h2 <= h2 + c;
				     h3 <= h3 + d;
					  h4 <= h4 + e;
				     h5 <= h5 + f;
				     h6 <= h6 + g;
					  h7 <= h7 + h;
					 end
					  
				  endcase
					  if (count == blocks) begin
					    m <= 0;
					    mem_addr <= output_addr -1;
						 state <= DONE;
					  end
					  else begin
					    mem_addr <= mem_addr -1;
                   count <= count +1;
			          state <= INITIAL;
				      end
				  end
				  
		  DONE: begin 
			     mem_we<=1;
				  case(opcode)
					 2'b01: begin   
	             if (m < 5) begin
					 if(m==0) 
					    mem_write_data <= h0;
					 else if (m==1)
					    mem_write_data <= h1;
					 else if (m==2)
					    mem_write_data <= h2;
					 else if (m==3)
					    mem_write_data <= h3;
					 else 
					    mem_write_data <= h4;					
					 mem_addr <= mem_addr +1;
					 m <= m+1;
					 state <= DONE;    
				   end
					  else begin
					    done <= 1;
					    state <= IDLE;
					  end
					end
					
					2'b00: begin
					if (m < 4) begin
					 if(m==0) 
					    mem_write_data <= h0;
					 else if (m==1)
					    mem_write_data <= h1;
					 else if (m==2)
					    mem_write_data <= h2;
					 else
					    mem_write_data <= h3;					
					 mem_addr <= mem_addr +1;
					 m <= m+1;
					 state <= DONE;    
				   end
					  else begin
					    done <= 1;
					    state <= IDLE;
					  end
					end
					
					2'b10: begin
					if (m < 8) begin
					 if(m==0) 
					    mem_write_data <= h0;
					 else if (m==1)
					    mem_write_data <= h1;
					 else if (m==2)
					    mem_write_data <= h2;
					 else if (m==3)
					    mem_write_data <= h3;
					 else if (m==4)
					    mem_write_data <= h4;
		          else if (m==5)
					    mem_write_data <= h5;
					 else if (m==6)
					    mem_write_data <= h6;
					 else
					    mem_write_data <= h7;				 
					 mem_addr <= mem_addr +1;
					 m <= m+1;
					 state <= DONE;    
				   end
					  else begin
					    done <= 1;
					    state <= IDLE;
					  end
					end
					
				 endcase
				 end  
	 
		endcase							
	 end 								 
  end									 
endmodule

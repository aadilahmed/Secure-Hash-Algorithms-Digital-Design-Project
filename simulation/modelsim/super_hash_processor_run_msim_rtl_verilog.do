transcript on
if {[file exists rtl_work]} {
	vdel -lib rtl_work -all
}
vlib rtl_work
vmap work rtl_work

vlog -sv -work work +incdir+C:/Users/Aadil/Desktop/Project_final_v1-20170605T004039Z-001/Project_final_v1 {C:/Users/Aadil/Desktop/Project_final_v1-20170605T004039Z-001/Project_final_v1/super_hash_processor.sv}


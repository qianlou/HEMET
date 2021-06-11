// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

//void convolution(Ciphertext Ciph_input, Plaintext Plan_weights, int Kernel_size, Ciphertext Ciph_output, Evaluator Eva, GaloisKeys GK)
//{
//    Eva.multiply_plain(Ciph_input, Plan_weights, Ciph_output);
//    Ciphertext Rotated_tmp, Result_tmp;
//    for (int i = 1; i < Kernel_size; i++)
//    {
//        Eva.rotate_vector(Ciph_input, i, GK, Rotated_tmp);
//        Eva.multiply_plain(Rotated_tmp, Plan_weights, Result_tmp);
//        Eva.add_inplace(Ciph_output, Result_tmp); 
//    }
//}



void squeeze()
{

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192*8 ;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}));

    double input_scale = pow(2.0, 25);
    double weight_scale = pow(2.0, 30);
    double scalar_scale = pow(2.0, 10);
    auto context = SEALContext::Create(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    GaloisKeys gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff0;
    //encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, weight_scale, plain_coeff3);
    encoder.encode(1.0, scalar_scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, input_scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);


    Ciphertext y_encrypted;
    print_line(__LINE__);

    double Mul_number[13] = { 1.728, 0.256, 2.048, 20.470, 2.048, 20.470, 0.256, 2.048, 40.960, 4.096, 40.960, 2.560, 1.280 };
    double Rot_number[13] = { 0.027, 0.256, 0.064, 0.320, 0.064, 0.320, 0.256, 0.064, 0.320, 0.128, 0.320, 0.256, 0.128};
    double Rot_Cost[13] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    double Mul_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rot_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    double Mul_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


    evaluator.multiply_plain(x1_encrypted, plain_coeff3, y_encrypted); //25+30=55, y_encrypted has 3 entries.
    Ciphertext Rotated_tmp, Result_tmp;
    int run_times = 10;
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(x1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); //25+30=55, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[0] += time_diff.count();
    }
    Rot_latency[0] = Rot_latency[0] / run_times;
    Mul_latency[0] = Mul_latency[0] / run_times;
    Rot_Cost[0] = Rot_latency[0] * Rot_number[0];
    Mul_Cost[0] = Mul_latency[0] * Mul_number[0];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); //25+30=55, y_encrypted has 2 entries.
   

    evaluator.square_inplace(y_encrypted); // 55^2=110
    evaluator.relinearize_inplace(y_encrypted, relin_keys); 
    evaluator.rescale_to_next_inplace(y_encrypted);//110-60=50
    //cout << "    + Scale of y_encrypted after square:  " << log2(y_encrypted.scale()) << " bits (50)" << endl;
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted,plain_coeff0);//50+10=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);//

    Ciphertext y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[1] += time_diff.count();
    }
    Rot_latency[1] = Rot_latency[1] / run_times;
    Mul_latency[1] = Mul_latency[1] / run_times;
    Rot_Cost[1] = Rot_latency[1] * Rot_number[1];
    Mul_Cost[1] = Mul_latency[1] * Mul_number[1];


    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30, y_encrypted has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[2] += time_diff.count();
    }
    Rot_latency[2] = Rot_latency[2] / run_times;
    Mul_latency[2] = Mul_latency[2] / run_times;
    Rot_Cost[2] = Rot_latency[2] * Rot_number[2];
    Mul_Cost[2] = Mul_latency[2] * Mul_number[2];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
 
    
    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[3] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[3] += time_diff.count();
    }
    Rot_latency[3] = Rot_latency[3] / run_times;
    Mul_latency[3] = Mul_latency[3] / run_times;
    Rot_Cost[3] = Rot_latency[3] * Rot_number[3];
    Mul_Cost[3] = Mul_latency[3] * Mul_number[3];


    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);



    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted); 
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[4] += time_diff.count();
    }

    Rot_latency[4] = Rot_latency[4] / run_times;
    Mul_latency[4] = Mul_latency[4] / run_times;
    Rot_Cost[4] = Rot_latency[4] * Rot_number[4];
    Mul_Cost[4] = Mul_latency[4] * Mul_number[4];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    y1_encrypted = y_encrypted;
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[5] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[5] += time_diff.count();
    }
    Rot_latency[5] = Rot_latency[5] / run_times;
    Mul_latency[5] = Mul_latency[5] / run_times;
    Rot_Cost[5] = Rot_latency[5] * Rot_number[5];
    Mul_Cost[5] = Mul_latency[5] * Mul_number[5];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    time_end = chrono::high_resolution_clock::now();
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "#### The ReLU5 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[6] += time_diff.count();
    }
    Rot_latency[6] = Rot_latency[6] / run_times;
    Mul_latency[6] = Mul_latency[6] / run_times;
    Rot_Cost[6] = Rot_latency[6] * Rot_number[6];
    Mul_Cost[6] = Mul_latency[6] * Mul_number[6];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
  
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[7] += time_diff.count();
    }
    Rot_latency[7] = Rot_latency[7] / run_times;
    Mul_latency[7] = Mul_latency[7] / run_times;
    Rot_Cost[7] = Rot_latency[7] * Rot_number[7];
    Mul_Cost[7] = Mul_latency[7] * Mul_number[7];


    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted); // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 30^2=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[8] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[8] += time_diff.count();
    }
    Rot_latency[8] = Rot_latency[8] / run_times;
    Mul_latency[8] = Mul_latency[8] / run_times;
    Rot_Cost[8] = Rot_latency[8] * Rot_number[8];
    Mul_Cost[8] = Mul_latency[8] * Mul_number[8];




    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[9] += time_diff.count();
    }
    Rot_latency[9] = Rot_latency[9] / run_times;
    Mul_latency[9] = Mul_latency[9] / run_times;
    Rot_Cost[9] = Rot_latency[9] * Rot_number[9];
    Mul_Cost[9] = Mul_latency[9] * Mul_number[9];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    //cout << "#### The Squeeze4 Done [" << Rot_Cost_list[9] +  Mul_Cost_list[9]  << " ms]" << endl;


    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    //cout << "#### The ReLU8 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[10] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[10] += time_diff.count();
    }
    Rot_latency[10] = Rot_latency[10] / run_times;
    Mul_latency[10] = Mul_latency[10] / run_times;
    Rot_Cost[10] = Rot_latency[10] * Rot_number[10];
    Mul_Cost[10] = Mul_latency[10] * Mul_number[10];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[11] += time_diff.count();
    }
    Rot_latency[11] = Rot_latency[11] / run_times;
    Mul_latency[11] = Mul_latency[11] / run_times;
    Rot_Cost[11] = Rot_latency[11] * Rot_number[11];
    Mul_Cost[11] = Mul_latency[11] * Mul_number[11];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[12] += time_diff.count();
    }
    Rot_latency[12] = Rot_latency[12] / run_times;
    Mul_latency[12] = Mul_latency[12] / run_times;
    Rot_Cost[12] = Rot_latency[12] * Rot_number[12];
    Mul_Cost[12] = Mul_latency[12] * Mul_number[12];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    evaluator.rescale_to_next_inplace(y_encrypted); // 90-30=60, Result_tmp has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    cout << "#### The pool3 Done [" << time_diff.count() << " microseconds]" << endl;

   for (int i = 0; i < 13; i++)
   {
       cout << "The " << i << " layer Rot latency is  [" << Rot_latency[i] << " ms]"
            << " Mult latency is " << +Mul_latency[i] << " ms]" << endl;
   }

   double Rot_latency_total = 0.0;
   double Mult_latency_total = 0.0;
   for (int i = 0; i < 13; i++)
    {
       cout << "The " << i << " layer **Total** Rot latency is  [" << Rot_Cost[i] << " ms]"
             << " **Total** Mult latency is " << +Mul_Cost[i] << " ms]" << endl;
        Rot_latency_total += Rot_Cost[i];
       Mult_latency_total += Mul_Cost[i];
    }

    cout << "The Rot latency is  [" << Rot_latency_total << " ms]"
         << " Mult latency is " << +Mult_latency_total << " ms]"
         << " Total latency is " << +(Rot_latency_total + Mult_latency_total) / 1000 << " s]" << endl;
}


void squeeze_relinearize()
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192 * 8;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60 }));

    double input_scale = pow(2.0, 25);
    double weight_scale = pow(2.0, 30);
    double scalar_scale = pow(2.0, 10);
    auto context = SEALContext::Create(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    GaloisKeys gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff0;
    // encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, weight_scale, plain_coeff3);
    encoder.encode(1.0, scalar_scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, input_scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext y_encrypted;
    print_line(__LINE__);

    double Mul_number[13] = { 1.728, 0.256,  2.048, 20.470, 2.048, 20.470, 0.256,
                              2.048, 40.960, 4.096, 40.960, 2.560, 1.280 };
    double Rot_number[13] = {
        0.027, 0.256, 0.064, 0.320, 0.064, 0.320, 0.256, 0.064, 0.320, 0.128, 0.320, 0.256, 0.128
    };
    double Rot_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rel_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rot_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rel_latency[13] = {0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    evaluator.multiply_plain(x1_encrypted, plain_coeff3, y_encrypted); // 25+30=55, y_encrypted has 3 entries.
    Ciphertext Rotated_tmp, Result_tmp;
    int run_times = 10;
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(x1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 25+30=55, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 25+30=55, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[0] += time_diff.count();
    }
    Rot_latency[0] = Rot_latency[0] / run_times;
    Mul_latency[0] = Mul_latency[0] / run_times;
    Rel_latency[0] = Rel_latency[0] / run_times;
    Rot_Cost[0] = Rot_latency[0] * Rot_number[0];
    Mul_Cost[0] = Mul_latency[0] * Mul_number[0];
    Rel_Cost[0] = Rel_latency[0] * Mul_number[0];
 

    evaluator.square_inplace(y_encrypted); // 55^2=110
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 110-60=50
    // cout << "    + Scale of y_encrypted after square:  " << log2(y_encrypted.scale()) << " bits (50)" << endl;
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 50+10=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //


    Ciphertext y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[1] += time_diff.count();
    }
    Rot_latency[1] = Rot_latency[1] / run_times;
    Mul_latency[1] = Mul_latency[1] / run_times;
    Rot_Cost[1] = Rot_latency[1] * Rot_number[1];
    Mul_Cost[1] = Mul_latency[1] * Mul_number[1];

    Rel_latency[1] = Rel_latency[1] / run_times;
    Rel_Cost[1] = Rel_latency[1] * Mul_number[1];

    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30, y_encrypted has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[2] += time_diff.count();

    }
    Rot_latency[2] = Rot_latency[2] / run_times;
    Mul_latency[2] = Mul_latency[2] / run_times;
    Rot_Cost[2] = Rot_latency[2] * Rot_number[2];
    Mul_Cost[2] = Mul_latency[2] * Mul_number[2];
    Rel_latency[2] = Rel_latency[2] / run_times;
    Rel_Cost[2] = Rel_latency[2] * Mul_number[2];

    cout << "#### The Squeeze1 Done ["
         << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU2 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[3] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[3] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[3] += time_diff.count();

    }
    Rot_latency[3] = Rot_latency[3] / run_times;
    Mul_latency[3] = Mul_latency[3] / run_times;
    Rot_Cost[3] = Rot_latency[3] * Rot_number[3];
    Mul_Cost[3] = Mul_latency[3] * Mul_number[3];
    Rel_latency[3] = Rel_latency[3] / run_times;
    Rel_Cost[3] = Rel_latency[3] * Mul_number[3];

    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[4] += time_diff.count();
    }

    Rot_latency[4] = Rot_latency[4] / run_times;
    Mul_latency[4] = Mul_latency[4] / run_times;
    Rot_Cost[4] = Rot_latency[4] * Rot_number[4];
    Mul_Cost[4] = Mul_latency[4] * Mul_number[4];
    Rel_latency[4] = Rel_latency[4] / run_times;
    Rel_Cost[4] = Rel_latency[4] * Mul_number[4];


    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    y1_encrypted = y_encrypted;
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[5] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[5] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[5] += time_diff.count();
    }
    Rot_latency[5] = Rot_latency[5] / run_times;
    Mul_latency[5] = Mul_latency[5] / run_times;
    Rot_Cost[5] = Rot_latency[5] * Rot_number[5];
    Mul_Cost[5] = Mul_latency[5] * Mul_number[5];
    Rel_latency[5] = Rel_latency[5] / run_times;
    Rel_Cost[5] = Rel_latency[5] * Mul_number[5];



    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    time_end = chrono::high_resolution_clock::now();
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "#### The ReLU5 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[6] += time_diff.count();

    }
    Rot_latency[6] = Rot_latency[6] / run_times;
    Mul_latency[6] = Mul_latency[6] / run_times;
    Rot_Cost[6] = Rot_latency[6] * Rot_number[6];
    Mul_Cost[6] = Mul_latency[6] * Mul_number[6];
    Rel_latency[6] = Rel_latency[6] / run_times;
    Rel_Cost[6] = Rel_latency[6] * Mul_number[6];

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[7] += time_diff.count();

    }
    Rot_latency[7] = Rot_latency[7] / run_times;
    Mul_latency[7] = Mul_latency[7] / run_times;
    Rot_Cost[7] = Rot_latency[7] * Rot_number[7];
    Mul_Cost[7] = Mul_latency[7] * Mul_number[7];
    Rel_latency[7] = Rel_latency[7] / run_times;
    Rel_Cost[7] = Rel_latency[7] * Mul_number[7];

    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    evaluator.square_inplace(y_encrypted); // 30^2=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[8] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[8] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[8] += time_diff.count();

    }
    Rot_latency[8] = Rot_latency[8] / run_times;
    Mul_latency[8] = Mul_latency[8] / run_times;
    Rot_Cost[8] = Rot_latency[8] * Rot_number[8];
    Mul_Cost[8] = Mul_latency[8] * Mul_number[8];
    Rel_latency[8] = Rel_latency[8] / run_times;
    Rel_Cost[8] = Rel_latency[8] * Mul_number[8];

    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[9] += time_diff.count();

    }
    Rot_latency[9] = Rot_latency[9] / run_times;
    Mul_latency[9] = Mul_latency[9] / run_times;
    Rot_Cost[9] = Rot_latency[9] * Rot_number[9];
    Mul_Cost[9] = Mul_latency[9] * Mul_number[9];
    Rel_latency[9] = Rel_latency[9] / run_times;
    Rel_Cost[9] = Rel_latency[9] * Mul_number[9];


    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    y1_encrypted = y_encrypted;
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[10] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[10] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[10] += time_diff.count();

    }
    Rot_latency[10] = Rot_latency[10] / run_times;
    Mul_latency[10] = Mul_latency[10] / run_times;
    Rot_Cost[10] = Rot_latency[10] * Rot_number[10];
    Mul_Cost[10] = Mul_latency[10] * Mul_number[10];
    Rel_latency[10] = Rel_latency[10] / run_times;
    Rel_Cost[10] = Rel_latency[10] * Mul_number[10];


    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[11] += time_diff.count();


    }
    Rot_latency[11] = Rot_latency[11] / run_times;
    Mul_latency[11] = Mul_latency[11] / run_times;
    Rot_Cost[11] = Rot_latency[11] * Rot_number[11];
    Mul_Cost[11] = Mul_latency[11] * Mul_number[11];
    Rel_latency[11] = Rel_latency[11] / run_times;
    Rel_Cost[11] = Rel_latency[11] * Mul_number[11];


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rel_latency[12] += time_diff.count();

    }
    Rot_latency[12] = Rot_latency[12] / run_times;
    Mul_latency[12] = Mul_latency[12] / run_times;
    Rot_Cost[12] = Rot_latency[12] * Rot_number[12];
    Mul_Cost[12] = Mul_latency[12] * Mul_number[12];
    Rel_latency[12] = Rel_latency[12] / run_times;
    Rel_Cost[12] = Rel_latency[12] * Mul_number[12];


    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    evaluator.rescale_to_next_inplace(y_encrypted); // 90-30=60, Result_tmp has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    cout << "#### The pool3 Done [" << time_diff.count() << " microseconds]" << endl;

    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer Rot latency is  [" << Rot_latency[i] << " ms]"
             << " Mult latency is " << +Mul_latency[i] << " ms]" 
            << " Relinear. latency is " << +Rel_latency[i] << " ms]" 
            << endl;
    }

    double Rot_latency_total = 0.0;
    double Mult_latency_total = 0.0;
    double Rel_latency_total = 0.0;
    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer **Total** Rot latency is  [" << Rot_Cost[i] << " ms]"
             << " **Total** Mult latency is " << +Mul_Cost[i] << " ms]" 
            << " **Total** Rel latency is " << +Rel_Cost[i] << " ms]" 
            << endl;
        Rot_latency_total += Rot_Cost[i];
        Mult_latency_total += Mul_Cost[i];
        Rel_latency_total += Rel_Cost[i];
    }

    cout << "The Rot latency is  [" << Rot_latency_total << " ms]"
         << " Mult latency is " << Mult_latency_total << " ms]"
         << " Total latency is " << (Rot_latency_total + Mult_latency_total) / 1000 << " s]" 
        << " The Relinear. latency is " << Rel_latency_total / 1000 << " s]" 
        << endl;
}


void remove_fire4()
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192*4;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60 }));

    double input_scale = pow(2.0, 25);
    double weight_scale = pow(2.0, 30);
    double scalar_scale = pow(2.0, 10);
    auto context = SEALContext::Create(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    GaloisKeys gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff0;
    // encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, weight_scale, plain_coeff3);
    encoder.encode(1.0, scalar_scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, input_scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext y_encrypted;
    print_line(__LINE__);

    double Mul_number[13] = { 1.728, 0.256,  2.048, 20.470, 2.048, 20.470, 0.256,
                              2.048, 40.960, 90, 0, 2.560, 1.280 };
    double Rot_number[13] = {
        0.027, 0.256, 0.064, 0.320, 0.064, 0.320, 0.256, 0.064, 0.320, 0.8, 0, 0.256, 0.128
    };
    double Rot_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rot_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    evaluator.multiply_plain(x1_encrypted, plain_coeff3, y_encrypted); // 25+30=55, y_encrypted has 3 entries.
    Ciphertext Rotated_tmp, Result_tmp;
    int run_times = 10;
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(x1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 25+30=55, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[0] += time_diff.count();
    }
    Rot_latency[0] = Rot_latency[0] / run_times;
    Mul_latency[0] = Mul_latency[0] / run_times;
    Rot_Cost[0] = Rot_latency[0] * Rot_number[0];
    Mul_Cost[0] = Mul_latency[0] * Mul_number[0];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 25+30=55, y_encrypted has 2 entries.

    evaluator.square_inplace(y_encrypted); // 55^2=110
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 110-60=50
    // cout << "    + Scale of y_encrypted after square:  " << log2(y_encrypted.scale()) << " bits (50)" << endl;
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 50+10=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    Ciphertext y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[1] += time_diff.count();
    }
    Rot_latency[1] = Rot_latency[1] / run_times;
    Mul_latency[1] = Mul_latency[1] / run_times;
    Rot_Cost[1] = Rot_latency[1] * Rot_number[1];
    Mul_Cost[1] = Mul_latency[1] * Mul_number[1];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30, y_encrypted has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[2] += time_diff.count();
    }
    Rot_latency[2] = Rot_latency[2] / run_times;
    Mul_latency[2] = Mul_latency[2] / run_times;
    Rot_Cost[2] = Rot_latency[2] * Rot_number[2];
    Mul_Cost[2] = Mul_latency[2] * Mul_number[2];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    cout << "#### The Squeeze1 Done ["
         << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[3] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[3] += time_diff.count();
    }
    Rot_latency[3] = Rot_latency[3] / run_times;
    Mul_latency[3] = Mul_latency[3] / run_times;
    Rot_Cost[3] = Rot_latency[3] * Rot_number[3];
    Mul_Cost[3] = Mul_latency[3] * Mul_number[3];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[4] += time_diff.count();
    }

    Rot_latency[4] = Rot_latency[4] / run_times;
    Mul_latency[4] = Mul_latency[4] / run_times;
    Rot_Cost[4] = Rot_latency[4] * Rot_number[4];
    Mul_Cost[4] = Mul_latency[4] * Mul_number[4];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU4 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[5] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[5] += time_diff.count();
    }
    Rot_latency[5] = Rot_latency[5] / run_times;
    Mul_latency[5] = Mul_latency[5] / run_times;
    Rot_Cost[5] = Rot_latency[5] * Rot_number[5];
    Mul_Cost[5] = Mul_latency[5] * Mul_number[5];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    time_end = chrono::high_resolution_clock::now();
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "#### The ReLU5 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[6] += time_diff.count();
    }
    Rot_latency[6] = Rot_latency[6] / run_times;
    Mul_latency[6] = Mul_latency[6] / run_times;
    Rot_Cost[6] = Rot_latency[6] * Rot_number[6];
    Mul_Cost[6] = Mul_latency[6] * Mul_number[6];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[7] += time_diff.count();
    }
    Rot_latency[7] = Rot_latency[7] / run_times;
    Mul_latency[7] = Mul_latency[7] / run_times;
    Rot_Cost[7] = Rot_latency[7] * Rot_number[7];
    Mul_Cost[7] = Mul_latency[7] * Mul_number[7];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    // cout << "#### The Squeeze3 Done [" << Rot_Cost_list[7] + Mul_Cost_list[7] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 30^2=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[8] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[8] += time_diff.count();
    }
    Rot_latency[8] = Rot_latency[8] / run_times;
    Mul_latency[8] = Mul_latency[8] / run_times;
    Rot_Cost[8] = Rot_latency[8] * Rot_number[8];
    Mul_Cost[8] = Mul_latency[8] * Mul_number[8];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[9] += time_diff.count();
    }
    Rot_latency[9] = Rot_latency[9] / run_times;
    Mul_latency[9] = Mul_latency[9] / run_times;
    Rot_Cost[9] = Rot_latency[9] * Rot_number[9];
    Mul_Cost[9] = Mul_latency[9] * Mul_number[9];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

 

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[11] += time_diff.count();
    }
    Rot_latency[11] = Rot_latency[11] / run_times;
    Mul_latency[11] = Mul_latency[11] / run_times;
    Rot_Cost[11] = Rot_latency[11] * Rot_number[11];
    Mul_Cost[11] = Mul_latency[11] * Mul_number[11];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff0, y_encrypted); // 40+10=50, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff0, Result_tmp); // 40+10=50, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[12] += time_diff.count();
    }
    Rot_latency[12] = Rot_latency[12] / run_times;
    Mul_latency[12] = Mul_latency[12] / run_times;
    Rot_Cost[12] = Rot_latency[12] * Rot_number[12];
    Mul_Cost[12] = Mul_latency[12] * Mul_number[12];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 50, y_encrypted has 2 entries.
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    
    cout << "#### The pool3 Done [" << time_diff.count() << " microseconds]" << endl;

    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer Rot latency is  [" << Rot_latency[i] << " ms]"
             << " Mult latency is " << +Mul_latency[i] << " ms]" << endl;
    }

    double Rot_latency_total = 0.0;
    double Mult_latency_total = 0.0;
    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer **Total** Rot latency is  [" << Rot_Cost[i] << " ms]"
             << " **Total** Mult latency is " << +Mul_Cost[i] << " ms]" << endl;
        Rot_latency_total += Rot_Cost[i];
        Mult_latency_total += Mul_Cost[i];
    }

    cout << "The Rot latency is  [" << Rot_latency_total << " ms]"
         << " Mult latency is " << +Mult_latency_total << " ms]"
         << " Total latency is " << +(Rot_latency_total + Mult_latency_total) / 1000 << " s]" << endl;
}


void remove_fire34()
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192*4;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, { 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60 }));

    double input_scale = pow(2.0, 25);
    double weight_scale = pow(2.0, 30);
    double scalar_scale = pow(2.0, 10);
    auto context = SEALContext::Create(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    GaloisKeys gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff0;
    // encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, weight_scale, plain_coeff3);
    encoder.encode(1.0, scalar_scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, input_scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext y_encrypted;
    print_line(__LINE__);

    double Mul_number[13] = { 1.728, 0.256, 2.048, 20.470, 2.048, 20.470, 0.256, 73, 0, 90, 0, 2.560, 1.280 };
    double Rot_number[13] = { 0.027, 0.256, 0.064, 0.320, 0.064, 0.320, 0.256, 0.576, 0, 0.8, 0, 0.256, 0.128 };
    double Rot_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rot_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    evaluator.multiply_plain(x1_encrypted, plain_coeff3, y_encrypted); // 25+30=55, y_encrypted has 3 entries.
    Ciphertext Rotated_tmp, Result_tmp;
    int run_times = 10;
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(x1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 25+30=55, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[0] += time_diff.count();
    }
    Rot_latency[0] = Rot_latency[0] / run_times;
    Mul_latency[0] = Mul_latency[0] / run_times;
    Rot_Cost[0] = Rot_latency[0] * Rot_number[0];
    Mul_Cost[0] = Mul_latency[0] * Mul_number[0];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 25+30=55, y_encrypted has 2 entries.

    evaluator.square_inplace(y_encrypted); // 55^2=110
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 110-60=50
    // cout << "    + Scale of y_encrypted after square:  " << log2(y_encrypted.scale()) << " bits (50)" << endl;
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 50+10=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    Ciphertext y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[1] += time_diff.count();
    }
    Rot_latency[1] = Rot_latency[1] / run_times;
    Mul_latency[1] = Mul_latency[1] / run_times;
    Rot_Cost[1] = Rot_latency[1] * Rot_number[1];
    Mul_Cost[1] = Mul_latency[1] * Mul_number[1];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30, y_encrypted has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[2] += time_diff.count();
    }
    Rot_latency[2] = Rot_latency[2] / run_times;
    Mul_latency[2] = Mul_latency[2] / run_times;
    Rot_Cost[2] = Rot_latency[2] * Rot_number[2];
    Mul_Cost[2] = Mul_latency[2] * Mul_number[2];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    cout << "#### The Squeeze1 Done ["
         << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[3] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[3] += time_diff.count();
    }
    Rot_latency[3] = Rot_latency[3] / run_times;
    Mul_latency[3] = Mul_latency[3] / run_times;
    Rot_Cost[3] = Rot_latency[3] * Rot_number[3];
    Mul_Cost[3] = Mul_latency[3] * Mul_number[3];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The Expand1 Done [" << Mul_Cost_list[3] + Rot_Cost_list[3] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);   // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The ReLU3 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[4] += time_diff.count();
    }

    Rot_latency[4] = Rot_latency[4] / run_times;
    Mul_latency[4] = Mul_latency[4] / run_times;
    Rot_Cost[4] = Rot_latency[4] * Rot_number[4];
    Mul_Cost[4] = Mul_latency[4] * Mul_number[4];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //


    y1_encrypted = y_encrypted;
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[5] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[5] += time_diff.count();
    }
    Rot_latency[5] = Rot_latency[5] / run_times;
    Mul_latency[5] = Mul_latency[5] / run_times;
    Rot_Cost[5] = Rot_latency[5] * Rot_number[5];
    Mul_Cost[5] = Mul_latency[5] * Mul_number[5];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The Expand2 Done [" << Mul_Cost_list[5] + Rot_Cost_list[5]  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    time_end = chrono::high_resolution_clock::now();
    evaluator.rescale_to_next_inplace(y_encrypted);   //90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "#### The ReLU5 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[6] += time_diff.count();
    }
    Rot_latency[6] = Rot_latency[6] / run_times;
    Mul_latency[6] = Mul_latency[6] / run_times;
    Rot_Cost[6] = Rot_latency[6] * Rot_number[6];
    Mul_Cost[6] = Mul_latency[6] * Mul_number[6];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 30+30=60, y_encrypted has 2 entries.
    y1_encrypted = y_encrypted;



    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[7] += time_diff.count();
    }
    Rot_latency[7] = Rot_latency[7] / run_times;
    Mul_latency[7] = Mul_latency[7] / run_times;
    Rot_Cost[7] = Rot_latency[7] * Rot_number[7];
    Mul_Cost[7] = Mul_latency[7] * Mul_number[7];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    // cout << "#### The Squeeze3 Done [" << Rot_Cost_list[7] + Mul_Cost_list[7] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 30^2=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU6 Done [" << time_diff.count() << " microseconds]" << endl;


    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[9] += time_diff.count();
    }
    Rot_latency[9] = Rot_latency[9] / run_times;
    Mul_latency[9] = Mul_latency[9] / run_times;
    Rot_Cost[9] = Rot_latency[9] * Rot_number[9];
    Mul_Cost[9] = Mul_latency[9] * Mul_number[9];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.

    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    // cout << "#### The Squeeze4 Done [" << Rot_Cost_list[9] +  Mul_Cost_list[9]  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
   
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);              // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // cout << "#### The ReLU8 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[11] += time_diff.count();
    }
    Rot_latency[11] = Rot_latency[11] / run_times;
    Mul_latency[11] = Mul_latency[11] / run_times;
    Rot_Cost[11] = Rot_latency[11] * Rot_number[11];
    Mul_Cost[11] = Mul_latency[11] * Mul_number[11];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    // cout << "#### The Conv2 Done [" << Rot_Cost_list[11] + Mul_Cost_list[11] << " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff0, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff0, Result_tmp); // 60+300=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[12] += time_diff.count();
    }
    Rot_latency[12] = Rot_latency[12] / run_times;
    Mul_latency[12] = Mul_latency[12] / run_times;
    Rot_Cost[12] = Rot_latency[12] * Rot_number[12];
    Mul_Cost[12] = Mul_latency[12] * Mul_number[12];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);

    cout << "#### The pool3 Done [" << time_diff.count() << " microseconds]" << endl;

    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer Rot latency is  [" << Rot_latency[i] << " ms]"
             << " Mult latency is " << +Mul_latency[i] << " ms]" << endl;
    }

    double Rot_latency_total = 0.0;
    double Mult_latency_total = 0.0;
    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer **Total** Rot latency is  [" << Rot_Cost[i] << " ms]"
             << " **Total** Mult latency is " << +Mul_Cost[i] << " ms]" << endl;
        Rot_latency_total += Rot_Cost[i];
        Mult_latency_total += Mul_Cost[i];
    }

    cout << "The Rot latency is  [" << Rot_latency_total << " ms]"
         << " Mult latency is " << +Mult_latency_total << " ms]"
         << " Total latency is " << +(Rot_latency_total + Mult_latency_total) / 1000 << " s]" << endl;
}


void remove_fire34_merge()
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192 ;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, { 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60 }));

    double input_scale = pow(2.0, 25);
    double weight_scale = pow(2.0, 15);
    double scalar_scale = pow(2.0, 15);
    auto context = SEALContext::Create(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    GaloisKeys gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff0;
    // encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, weight_scale, plain_coeff3);
    encoder.encode(1.0, scalar_scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, input_scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext y_encrypted;
    print_line(__LINE__);

    double Mul_number[13] = { 1.728, 0.256, 2.048, 20.470, 2.048, 20.470, 0.256, 73, 0, 90, 0, 2.560, 1.280 };
    double Rot_number[13] = { 0.027, 0.256, 0.064, 0.320, 0.064, 0.320, 0.256, 0.576, 0, 0.8, 0, 0.256, 0.128 };
    double Rot_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rot_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    evaluator.multiply_plain(x1_encrypted, plain_coeff3, y_encrypted); // 25+15=40, y_encrypted has 3 entries.
    Ciphertext Rotated_tmp, Result_tmp;
    int run_times = 10;
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(x1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 25+15=40, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[0] += time_diff.count();
    }
    Rot_latency[0] = Rot_latency[0] / run_times;
    Mul_latency[0] = Mul_latency[0] / run_times;
    Rot_Cost[0] = Rot_latency[0] * Rot_number[0];
    Mul_Cost[0] = Mul_latency[0] * Mul_number[0];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 25+15=40, y_encrypted has 2 entries.
    // cout << "#### The conv1 Done [" << Mul_Cost[0] + Rot_Cost[0] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+15=95
    evaluator.rescale_to_next_inplace(y_encrypted);              // 95-60=35
    // cout << "    + Scale of y_encrypted after square:  " << log2(y_encrypted.scale()) << " bits (50)" << endl;
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    // cout << "    + Scale of x1_encrypted after ReLU1: " << log2(y_encrypted.scale()) << " bits" << endl;
    // cout << "#### The ReLU1 Done [" << time_diff.count() << " microseconds]" << endl;

    Ciphertext y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 35+15=50, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 35+15=50, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[1] += time_diff.count();
    }
    Rot_latency[1] = Rot_latency[1] / run_times;
    Mul_latency[1] = Mul_latency[1] / run_times;
    Rot_Cost[1] = Rot_latency[1] * Rot_number[1];
    Mul_Cost[1] = Mul_latency[1] * Mul_number[1];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 35+15=50, y_encrypted has 2 entries.
  
    // cout << "    + Scale of y_encrypted after pool: " << log2(y_encrypted.scale()) << " bits (30)" << endl;
    // cout << "#### The Pool Done [" << Mul_Cost_list[1] + Rot_Cost_list[1] << " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 50+15=65, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 50+15=65, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[2] += time_diff.count();
    }
    Rot_latency[2] = Rot_latency[2] / run_times;
    Mul_latency[2] = Mul_latency[2] / run_times;
    Rot_Cost[2] = Rot_latency[2] * Rot_number[2];
    Mul_Cost[2] = Mul_latency[2] * Mul_number[2];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 65, y_encrypted has 2 entries.

    cout << "#### The Squeeze1 Done ["
         << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 65^2=130
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 130-60=70, y_encrypted has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 70+15=85
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU2 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 85+15=105, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[3] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 85+15=105, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[3] += time_diff.count();
    }
    Rot_latency[3] = Rot_latency[3] / run_times;
    Mul_latency[3] = Mul_latency[3] / run_times;
    Rot_Cost[3] = Rot_latency[3] * Rot_number[3];
    Mul_Cost[3] = Mul_latency[3] * Mul_number[3];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 105, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 105-60=45
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The Expand1 Done [" << Mul_Cost_list[3] + Rot_Cost_list[3] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 45^2=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.relinearize_inplace(y_encrypted, relin_keys); //
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 30+15=45


    // cout << "#### The ReLU3 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 45+15=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 45+15=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[4] += time_diff.count();
    }

    Rot_latency[4] = Rot_latency[4] / run_times;
    Mul_latency[4] = Mul_latency[4] / run_times;
    Rot_Cost[4] = Rot_latency[4] * Rot_number[4];
    Mul_Cost[4] = Mul_latency[4] * Mul_number[4];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    // cout << "#### The Squeeze2 Done [" << Mul_Cost_list[4] + Rot_Cost_list[4] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+15=75
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU4 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 75+15=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[5] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 75+15=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[5] += time_diff.count();
    }
    Rot_latency[5] = Rot_latency[5] / run_times;
    Mul_latency[5] = Mul_latency[5] / run_times;
    Rot_Cost[5] = Rot_latency[5] * Rot_number[5];
    Mul_Cost[5] = Mul_latency[5] * Mul_number[5];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The Expand2 Done [" << Mul_Cost_list[5] + Rot_Cost_list[5]  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 30^2=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+15=75
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "#### The ReLU5 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 75+15=90, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 75+15=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[6] += time_diff.count();
    }
    Rot_latency[6] = Rot_latency[6] / run_times;
    Mul_latency[6] = Mul_latency[6] / run_times;
    Rot_Cost[6] = Rot_latency[6] * Rot_number[6];
    Mul_Cost[6] = Mul_latency[6] * Mul_number[6];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 75+15=90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    y1_encrypted = y_encrypted;

    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+15=45, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+15=45, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[7] += time_diff.count();
    }
    Rot_latency[7] = Rot_latency[7] / run_times;
    Mul_latency[7] = Mul_latency[7] / run_times;
    Rot_Cost[7] = Rot_latency[7] * Rot_number[7];
    Mul_Cost[7] = Mul_latency[7] * Mul_number[7];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 45, y_encrypted has 2 entries.

    // cout << "#### The Squeeze3 Done [" << Rot_Cost_list[7] + Mul_Cost_list[7] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 45^2=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 30+15=45
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU6 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 45+15=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 45+15=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[9] += time_diff.count();
    }
    Rot_latency[9] = Rot_latency[9] / run_times;
    Mul_latency[9] = Mul_latency[9] / run_times;
    Rot_Cost[9] = Rot_latency[9] * Rot_number[9];
    Mul_Cost[9] = Mul_latency[9] * Mul_number[9];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.


    // cout << "#### The Squeeze4 Done [" << Rot_Cost_list[9] +  Mul_Cost_list[9]  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+15=75
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
  
    // cout << "#### The ReLU8 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 75+15=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 75+15=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[11] += time_diff.count();
    }
    Rot_latency[11] = Rot_latency[11] / run_times;
    Mul_latency[11] = Mul_latency[11] / run_times;
    Rot_Cost[11] = Rot_latency[11] * Rot_number[11];
    Mul_Cost[11] = Mul_latency[11] * Mul_number[11];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // cout << "#### The Conv2 Done [" << Rot_Cost_list[11] + Mul_Cost_list[11] << " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff0, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff0, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[12] += time_diff.count();
    }
    Rot_latency[12] = Rot_latency[12] / run_times;
    Mul_latency[12] = Mul_latency[12] / run_times;
    Rot_Cost[12] = Rot_latency[12] * Rot_number[12];
    Mul_Cost[12] = Mul_latency[12] * Mul_number[12];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);

    cout << "#### The pool3 Done [" << time_diff.count() << " microseconds]" << endl;

    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer Rot latency is  [" << Rot_latency[i] << " ms]"
             << " Mult latency is " << +Mul_latency[i] << " ms]" << endl;
    }

    double Rot_latency_total = 0.0;
    double Mult_latency_total = 0.0;
    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer **Total** Rot latency is  [" << Rot_Cost[i] << " ms]"
             << " **Total** Mult latency is " << +Mul_Cost[i] << " ms]" << endl;
        Rot_latency_total += Rot_Cost[i];
        Mult_latency_total += Mul_Cost[i];
    }

    cout << "The Rot latency is  [" << Rot_latency_total << " ms]"
         << " Mult latency is " << +Mult_latency_total << " ms]"
         << " Total latency is " << +(Rot_latency_total + Mult_latency_total) / 1000 << " s]" << endl;
}




void remove_fire34_merge_eager()
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, {60, 60, 60, 60, 60, 60, 30, 60, 60, 60, 60, 60 }));

    double input_scale = pow(2.0, 25);
    double weight_scale = pow(2.0, 15);
    double scalar_scale = pow(2.0, 15);
    auto context = SEALContext::Create(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    GaloisKeys gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff0;
    // encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, weight_scale, plain_coeff3);
    encoder.encode(1.0, scalar_scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, input_scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext y_encrypted;
    print_line(__LINE__);

    double Mul_number[13] = { 1.728, 0.256, 2.048, 20.470, 2.048, 20.470, 0.256, 73, 0, 90, 0, 2.560, 1.280 };
    double Rot_number[13] = { 0.027, 0.256, 0.064, 0.320, 0.064, 0.320, 0.256, 0.576, 0, 0.8, 0, 0.256, 0.128 };
    double Rot_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rot_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    evaluator.multiply_plain(x1_encrypted, plain_coeff3, y_encrypted); // 25+15=40, y_encrypted has 3 entries.
    Ciphertext Rotated_tmp, Result_tmp;
    int run_times = 10;
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(x1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 25+15=40, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[0] += time_diff.count();
    }
    Rot_latency[0] = Rot_latency[0] / run_times;
    Mul_latency[0] = Mul_latency[0] / run_times;
    Rot_Cost[0] = Rot_latency[0] * Rot_number[0];
    Mul_Cost[0] = Mul_latency[0] * Mul_number[0];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 25+15=40, y_encrypted has 2 entries.
    // cout << "#### The conv1 Done [" << Mul_Cost[0] + Rot_Cost[0] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+15=95
    evaluator.rescale_to_next_inplace(y_encrypted);              // 95-60=35
    // cout << "    + Scale of y_encrypted after square:  " << log2(y_encrypted.scale()) << " bits (50)" << endl;
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.relinearize_inplace(y_encrypted, relin_keys); //

    // cout << "    + Scale of x1_encrypted after ReLU1: " << log2(y_encrypted.scale()) << " bits" << endl;
    // cout << "#### The ReLU1 Done [" << time_diff.count() << " microseconds]" << endl;

    Ciphertext y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 35+15=50, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 35+15=50, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[1] += time_diff.count();
    }
    Rot_latency[1] = Rot_latency[1] / run_times;
    Mul_latency[1] = Mul_latency[1] / run_times;
    Rot_Cost[1] = Rot_latency[1] * Rot_number[1];
    Mul_Cost[1] = Mul_latency[1] * Mul_number[1];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 35+15=50, y_encrypted has 2 entries.

    // cout << "    + Scale of y_encrypted after pool: " << log2(y_encrypted.scale()) << " bits (30)" << endl;
    // cout << "#### The Pool Done [" << Mul_Cost_list[1] + Rot_Cost_list[1] << " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 50+15=65, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 50+15=65, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[2] += time_diff.count();
    }
    Rot_latency[2] = Rot_latency[2] / run_times;
    Mul_latency[2] = Mul_latency[2] / run_times;
    Rot_Cost[2] = Rot_latency[2] * Rot_number[2];
    Mul_Cost[2] = Mul_latency[2] * Mul_number[2];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 65, y_encrypted has 2 entries.

    cout << "#### The Squeeze1 Done ["
         << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 65^2=130
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 130-60=70, y_encrypted has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 70+15=85
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU2 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 85+15=105, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[3] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 85+15=105, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[3] += time_diff.count();
    }
    Rot_latency[3] = Rot_latency[3] / run_times;
    Mul_latency[3] = Mul_latency[3] / run_times;
    Rot_Cost[3] = Rot_latency[3] * Rot_number[3];
    Mul_Cost[3] = Mul_latency[3] * Mul_number[3];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 105, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 105-60=45
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The Expand1 Done [" << Mul_Cost_list[3] + Rot_Cost_list[3] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 45^2=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.relinearize_inplace(y_encrypted, relin_keys); //
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 30+15=45

    // cout << "#### The ReLU3 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 45+15=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 45+15=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[4] += time_diff.count();
    }

    Rot_latency[4] = Rot_latency[4] / run_times;
    Mul_latency[4] = Mul_latency[4] / run_times;
    Rot_Cost[4] = Rot_latency[4] * Rot_number[4];
    Mul_Cost[4] = Mul_latency[4] * Mul_number[4];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    // cout << "#### The Squeeze2 Done [" << Mul_Cost_list[4] + Rot_Cost_list[4] << " ms]" << endl;

    evaluator.rescale_to_next_inplace(y_encrypted); // 60-30=30
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.square_inplace(y_encrypted); // 30^2=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+15=75
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU4 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;

    // evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 75+15=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[5] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 75+15=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[5] += time_diff.count();
    }
    Rot_latency[5] = Rot_latency[5] / run_times;
    Mul_latency[5] = Mul_latency[5] / run_times;
    Rot_Cost[5] = Rot_latency[5] * Rot_number[5];
    Mul_Cost[5] = Mul_latency[5] * Mul_number[5];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The Expand2 Done [" << Mul_Cost_list[5] + Rot_Cost_list[5]  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 30^2=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+15=75
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "#### The ReLU5 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 75+15=90, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 75+15=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[6] += time_diff.count();
    }
    Rot_latency[6] = Rot_latency[6] / run_times;
    Mul_latency[6] = Mul_latency[6] / run_times;
    Rot_Cost[6] = Rot_latency[6] * Rot_number[6];
    Mul_Cost[6] = Mul_latency[6] * Mul_number[6];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 75+15=90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    y1_encrypted = y_encrypted;

    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+15=45, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+15=45, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[7] += time_diff.count();
    }
    Rot_latency[7] = Rot_latency[7] / run_times;
    Mul_latency[7] = Mul_latency[7] / run_times;
    Rot_Cost[7] = Rot_latency[7] * Rot_number[7];
    Mul_Cost[7] = Mul_latency[7] * Mul_number[7];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 45, y_encrypted has 2 entries.

    // cout << "#### The Squeeze3 Done [" << Rot_Cost_list[7] + Mul_Cost_list[7] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 45^2=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 30+15=45
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU6 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 45+15=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 45+15=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[9] += time_diff.count();
    }
    Rot_latency[9] = Rot_latency[9] / run_times;
    Mul_latency[9] = Mul_latency[9] / run_times;
    Rot_Cost[9] = Rot_latency[9] * Rot_number[9];
    Mul_Cost[9] = Mul_latency[9] * Mul_number[9];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    // cout << "#### The Squeeze4 Done [" << Rot_Cost_list[9] +  Mul_Cost_list[9]  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+15=75
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    // cout << "#### The ReLU8 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 75+15=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 75+15=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[11] += time_diff.count();
    }
    Rot_latency[11] = Rot_latency[11] / run_times;
    Mul_latency[11] = Mul_latency[11] / run_times;
    Rot_Cost[11] = Rot_latency[11] * Rot_number[11];
    Mul_Cost[11] = Mul_latency[11] * Mul_number[11];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // cout << "#### The Conv2 Done [" << Rot_Cost_list[11] + Mul_Cost_list[11] << " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff0, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff0, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[12] += time_diff.count();
    }
    Rot_latency[12] = Rot_latency[12] / run_times;
    Mul_latency[12] = Mul_latency[12] / run_times;
    Rot_Cost[12] = Rot_latency[12] * Rot_number[12];
    Mul_Cost[12] = Mul_latency[12] * Mul_number[12];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);

    cout << "#### The pool3 Done [" << time_diff.count() << " microseconds]" << endl;

    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer Rot latency is  [" << Rot_latency[i] << " ms]"
             << " Mult latency is " << +Mul_latency[i] << " ms]" << endl;
    }

    double Rot_latency_total = 0.0;
    double Mult_latency_total = 0.0;
    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer **Total** Rot latency is  [" << Rot_Cost[i] << " ms]"
             << " **Total** Mult latency is " << +Mul_Cost[i] << " ms]" << endl;
        Rot_latency_total += Rot_Cost[i];
        Mult_latency_total += Mul_Cost[i];
    }

    cout << "The Rot latency is  [" << Rot_latency_total << " ms]"
         << " Mult latency is " << +Mult_latency_total << " ms]"
         << " Total latency is " << +(Rot_latency_total + Mult_latency_total) / 1000 << " s]" << endl;
}



void remove_fire234()
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192*4;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, { 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60 }));

    double input_scale = pow(2.0, 25);
    double weight_scale = pow(2.0, 30);
    double scalar_scale = pow(2.0, 10);
    auto context = SEALContext::Create(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    GaloisKeys gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff0;
    // encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, weight_scale, plain_coeff3);
    encoder.encode(1.0, scalar_scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, input_scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext y_encrypted;
    print_line(__LINE__);

    double Mul_number[13] = { 1.728, 0.256, 2.048, 20.470, 36.864, 0, 0.256, 73, 0, 90, 0, 2.560, 1.280 };
    double Rot_number[13] = { 0.027, 0.256, 0.064, 0.320, 0.576, 0, 0.256, 0.576, 0, 0.8, 0, 0.256, 0.128 };
    double Rot_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rot_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    evaluator.multiply_plain(x1_encrypted, plain_coeff3, y_encrypted); // 25+30=55, y_encrypted has 3 entries.
    Ciphertext Rotated_tmp, Result_tmp;
    int run_times = 10;
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(x1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 25+30=55, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[0] += time_diff.count();
    }
    Rot_latency[0] = Rot_latency[0] / run_times;
    Mul_latency[0] = Mul_latency[0] / run_times;
    Rot_Cost[0] = Rot_latency[0] * Rot_number[0];
    Mul_Cost[0] = Mul_latency[0] * Mul_number[0];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 25+30=55, y_encrypted has 2 entries.
    // cout << "#### The conv1 Done [" << Mul_Cost[0] + Rot_Cost[0] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 55^2=110
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 110-60=50
    // cout << "    + Scale of y_encrypted after square:  " << log2(y_encrypted.scale()) << " bits (50)" << endl;
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 50+10=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    // cout << "    + Scale of x1_encrypted after ReLU1: " << log2(y_encrypted.scale()) << " bits" << endl;
    // cout << "#### The ReLU1 Done [" << time_diff.count() << " microseconds]" << endl;

    Ciphertext y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[1] += time_diff.count();
    }
    Rot_latency[1] = Rot_latency[1] / run_times;
    Mul_latency[1] = Mul_latency[1] / run_times;
    Rot_Cost[1] = Rot_latency[1] * Rot_number[1];
    Mul_Cost[1] = Mul_latency[1] * Mul_number[1];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30, y_encrypted has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    // cout << "    + Scale of y_encrypted after pool: " << log2(y_encrypted.scale()) << " bits (30)" << endl;
    // cout << "#### The Pool Done [" << Mul_Cost_list[1] + Rot_Cost_list[1] << " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[2] += time_diff.count();
    }
    Rot_latency[2] = Rot_latency[2] / run_times;
    Mul_latency[2] = Mul_latency[2] / run_times;
    Rot_Cost[2] = Rot_latency[2] * Rot_number[2];
    Mul_Cost[2] = Mul_latency[2] * Mul_number[2];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    cout << "#### The Squeeze1 Done ["
         << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU2 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[3] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[3] += time_diff.count();
    }
    Rot_latency[3] = Rot_latency[3] / run_times;
    Mul_latency[3] = Mul_latency[3] / run_times;
    Rot_Cost[3] = Rot_latency[3] * Rot_number[3];
    Mul_Cost[3] = Mul_latency[3] * Mul_number[3];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The Expand1 Done [" << Mul_Cost_list[3] + Rot_Cost_list[3] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 40^2=80
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The ReLU3 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[4] += time_diff.count();
    }

    Rot_latency[4] = Rot_latency[4] / run_times;
    Mul_latency[4] = Mul_latency[4] / run_times;
    Rot_Cost[4] = Rot_latency[4] * Rot_number[4];
    Mul_Cost[4] = Mul_latency[4] * Mul_number[4];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    // cout << "#### The Squeeze2 Done [" << Mul_Cost_list[4] + Rot_Cost_list[4] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    // cout << "#### The ReLU4 Done [" << time_diff.count() << " microseconds]" << endl;



    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[6] += time_diff.count();
    }
    Rot_latency[6] = Rot_latency[6] / run_times;
    Mul_latency[6] = Mul_latency[6] / run_times;
    Rot_Cost[6] = Rot_latency[6] * Rot_number[6];
    Mul_Cost[6] = Mul_latency[6] * Mul_number[6];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 70+30=100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 40+30=70, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 40+30=70, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[7] += time_diff.count();
    }
    Rot_latency[7] = Rot_latency[7] / run_times;
    Mul_latency[7] = Mul_latency[7] / run_times;
    Rot_Cost[7] = Rot_latency[7] * Rot_number[7];
    Mul_Cost[7] = Mul_latency[7] * Mul_number[7];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 70, y_encrypted has 2 entries.
    // cout << "#### The Squeeze3 Done [" << Rot_Cost_list[7] + Mul_Cost_list[7] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 70^2=140
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 140-60=80
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 80+10=90
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);              // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    // cout << "#### The ReLU6 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[9] += time_diff.count();
    }
    Rot_latency[9] = Rot_latency[9] / run_times;
    Mul_latency[9] = Mul_latency[9] / run_times;
    Rot_Cost[9] = Rot_latency[9] * Rot_number[9];
    Mul_Cost[9] = Mul_latency[9] * Mul_number[9];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.

    
    // cout << "#### The Squeeze4 Done [" << Rot_Cost_list[9] +  Mul_Cost_list[9]  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    // cout << "#### The ReLU8 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 70+30=100, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 70+30=100, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[11] += time_diff.count();
    }
    Rot_latency[11] = Rot_latency[11] / run_times;
    Mul_latency[11] = Mul_latency[11] / run_times;
    Rot_Cost[11] = Rot_latency[11] * Rot_number[11];
    Mul_Cost[11] = Mul_latency[11] * Mul_number[11];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 100, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 100-60=40
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    // cout << "#### The Conv2 Done [" << Rot_Cost_list[11] + Mul_Cost_list[11] << " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff0, y_encrypted); // 40+10=50, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff0, Result_tmp); // 40+10=50, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[12] += time_diff.count();
    }
    Rot_latency[12] = Rot_latency[12] / run_times;
    Mul_latency[12] = Mul_latency[12] / run_times;
    Rot_Cost[12] = Rot_latency[12] * Rot_number[12];
    Mul_Cost[12] = Mul_latency[12] * Mul_number[12];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 50, y_encrypted has 2 entries.

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);

    cout << "#### The pool3 Done [" << time_diff.count() << " microseconds]" << endl;

    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer Rot latency is  [" << Rot_latency[i] << " ms]"
             << " Mult latency is " << +Mul_latency[i] << " ms]" << endl;
    }

    double Rot_latency_total = 0.0;
    double Mult_latency_total = 0.0;
    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer **Total** Rot latency is  [" << Rot_Cost[i] << " ms]"
             << " **Total** Mult latency is " << +Mul_Cost[i] << " ms]" << endl;
        Rot_latency_total += Rot_Cost[i];
        Mult_latency_total += Mul_Cost[i];
    }

    cout << "The Rot latency is  [" << Rot_latency_total << " ms]"
         << " Mult latency is " << +Mult_latency_total << " ms]"
         << " Total latency is " << +(Rot_latency_total + Mult_latency_total) / 1000 << " s]" << endl;
}


void remove_fire1234()
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);


     parms.set_coeff_modulus(
     CoeffModulus::Create(poly_modulus_degree, {60, 60, 40, 60, 40, 60, 40, 60, 40, 60, 60, 60, 60 }));
    //parms.set_coeff_modulus(
     //   CoeffModulus::Create(poly_modulus_degree, { 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 40, 60, 60, 60, 60 }));
    // parms.set_coeff_modulus(CoeffModulus::Create(
    //     poly_modulus_degree, { 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60 }));

    double input_scale = pow(2.0, 25);
    double weight_scale = pow(2.0, 30);
    double scalar_scale = pow(2.0, 10);
    auto context = SEALContext::Create(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    GaloisKeys gal_keys = keygen.galois_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff0;
    // encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, weight_scale, plain_coeff3);
    encoder.encode(1.0, scalar_scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, input_scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext y_encrypted;
    print_line(__LINE__);

    // double HE_Mul_list[12] = { 1.728, 0.256, 36.864, 0, 2.048, 20.470, 0.256, 2.048, 40.960, 4.096, 40.960, 2.560 };
    // double HE_Rot_list[12] = { 0.027, 0.256, 0.576, 0, 0.064, 0.320, 0.256, 0.064, 0.320, 0.128, 0.320, 0.256 };

    //double HE_Mul_list[12] = { 1.728, 0.256, 2.048, 20.470, 36.864, 0, 0.256, 73.728, 0, 147.456, 0, 2.560 };
    //double HE_Rot_list[12] = { 0.027, 0.256, 0.064, 0.320, 0.576, 0, 0.256, 0.576, 0, 1.152, 0, 0.256 };


    double Mul_number[13] = { 1.728, 0.256, 36.864, 0, 36.864, 0, 0.256, 73.728, 0, 147.456, 0, 2.560, 1.280};
    double Rot_number[13] = { 0.027, 0.256, 0.576, 0, 0.576, 0, 0.256, 0.576, 0, 1.152, 0, 0.256, 0.128};
    double Rot_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_Cost[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Rot_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    double Mul_latency[13] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    evaluator.multiply_plain(x1_encrypted, plain_coeff3, y_encrypted); // 25+30=55, y_encrypted has 3 entries.
    Ciphertext Rotated_tmp, Result_tmp;
    int run_times = 10;
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(x1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[0] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 25+30=55, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[0] += time_diff.count();
    }
    Rot_latency[0] = Rot_latency[0] / run_times;
    Mul_latency[0] = Mul_latency[0] / run_times;
    Rot_Cost[0] = Rot_latency[0] * Rot_number[0];
    Mul_Cost[0] = Mul_latency[0] * Mul_number[0];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 25+30=55, y_encrypted has 2 entries.
     cout << "#### The conv1 Done ["  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 55^2=110
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 110-60=50
    // cout << "    + Scale of y_encrypted after square:  " << log2(y_encrypted.scale()) << " bits (50)" << endl;
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 50+10=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    // cout << "    + Scale of x1_encrypted after ReLU1: " << log2(y_encrypted.scale()) << " bits" << endl;
     cout << "#### The ReLU1 Done [" << " microseconds]" << endl;

    Ciphertext y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[1] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[1] += time_diff.count();
    }
    Rot_latency[1] = Rot_latency[1] / run_times;
    Mul_latency[1] = Mul_latency[1] / run_times;
    Rot_Cost[1] = Rot_latency[1] * Rot_number[1];
    Mul_Cost[1] = Mul_latency[1] * Mul_number[1];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30, y_encrypted has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    // cout << "    + Scale of y_encrypted after pool: " << log2(y_encrypted.scale()) << " bits (30)" << endl;
    // cout << "#### The Pool Done [" << Mul_Cost_list[1] + Rot_Cost_list[1] << " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[2] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[2] += time_diff.count();
    }
    Rot_latency[2] = Rot_latency[2] / run_times;
    Mul_latency[2] = Mul_latency[2] / run_times;
    Rot_Cost[2] = Rot_latency[2] * Rot_number[2];
    Mul_Cost[2] = Mul_latency[2] * Mul_number[2];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    // cout << "#### The Squeeze1 Done [" << Mul_Cost_list[2] + Rot_Cost_list[2] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70

    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 70-40=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);

    // cout << "#### The ReLU3 Done [" << time_diff.count() << " microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[4] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 30+30=60, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[4] += time_diff.count();
    }

    Rot_latency[4] = Rot_latency[4] / run_times;
    Mul_latency[4] = Mul_latency[4] / run_times;
    Rot_Cost[4] = Rot_latency[4] * Rot_number[4];
    Mul_Cost[4] = Mul_latency[4] * Mul_number[4];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    // cout << "#### The Squeeze2 Done [" << Mul_Cost_list[4] + Rot_Cost_list[4] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    
    evaluator.rescale_to_next_inplace(y_encrypted);  // 70-40=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);



    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.

    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[6] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[6] += time_diff.count();
    }
    Rot_latency[6] = Rot_latency[6] / run_times;
    Mul_latency[6] = Mul_latency[6] / run_times;
    Rot_Cost[6] = Rot_latency[6] * Rot_number[6];
    Mul_Cost[6] = Mul_latency[6] * Mul_number[6];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60+30=90, y_encrypted has 2 entries.
    y1_encrypted = y_encrypted;



    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[7] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[7] += time_diff.count();
    }
    Rot_latency[7] = Rot_latency[7] / run_times;
    Mul_latency[7] = Mul_latency[7] / run_times;
    Rot_Cost[7] = Rot_latency[7] * Rot_number[7];
    Mul_Cost[7] = Mul_latency[7] * Mul_number[7];

    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    evaluator.rescale_to_next_inplace(y_encrypted);         // 90-60=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    // cout << "#### The Squeeze3 Done [" << Rot_Cost_list[7] + Mul_Cost_list[7] << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 30^2=60
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //
    evaluator.rescale_to_next_inplace(y_encrypted);           //70-40=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    cout << "#### The ReLU7 Done  microseconds]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[9] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[9] += time_diff.count();
    }
    Rot_latency[9] = Rot_latency[9] / run_times;
    Mul_latency[9] = Mul_latency[9] / run_times;
    Rot_Cost[9] = Rot_latency[9] * Rot_number[9];
    Mul_Cost[9] = Mul_latency[9] * Mul_number[9];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
    // cout << "#### The Squeeze4 Done [" << Rot_Cost_list[9] +  Mul_Cost_list[9]  << " ms]" << endl;

    evaluator.square_inplace(y_encrypted); // 60^2=120
    evaluator.relinearize_inplace(y_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(y_encrypted); // 120-60=60
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.multiply_plain_inplace(y_encrypted, plain_coeff0); // 60+10=70
    evaluator.relinearize_inplace(y_encrypted, relin_keys);      //

    evaluator.rescale_to_next_inplace(y_encrypted);  // 70-40=30
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    cout << "#### The ReLU9 Done " << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 30+30=60, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[11] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[11] += time_diff.count();
    }
    Rot_latency[11] = Rot_latency[11] / run_times;
    Mul_latency[11] = Mul_latency[11] / run_times;
    Rot_Cost[11] = Rot_latency[11] * Rot_number[11];
    Mul_Cost[11] = Mul_latency[11] * Mul_number[11];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 60, y_encrypted has 2 entries.
     cout << "#### The Conv2 Done ["  " ms]" << endl;

    y1_encrypted = y_encrypted;
    evaluator.multiply_plain(y1_encrypted, plain_coeff3, y_encrypted); // 60+30=90, y_encrypted has 3 entries.
    for (int i = 1; i < run_times; i++)
    {
        time_start = chrono::high_resolution_clock::now();
        evaluator.rotate_vector(y1_encrypted, i, gal_keys, Rotated_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Rot_latency[12] += time_diff.count();

        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain(Rotated_tmp, plain_coeff3, Result_tmp); // 60+30=90, Result_tmp has 3 entries.
        evaluator.add_inplace(y_encrypted, Result_tmp);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        Mul_latency[12] += time_diff.count();
    }
    Rot_latency[12] = Rot_latency[12] / run_times;
    Mul_latency[12] = Mul_latency[12] / run_times;
    Rot_Cost[12] = Rot_latency[12] * Rot_number[12];
    Mul_Cost[12] = Mul_latency[12] * Mul_number[12];
    evaluator.relinearize_inplace(y_encrypted, relin_keys); // 90, y_encrypted has 2 entries.
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    evaluator.rescale_to_next_inplace(y_encrypted); // 90-30=60, Result_tmp has 2 entries.
    evaluator.mod_switch_to_next_inplace(plain_coeff3);
    evaluator.mod_switch_to_next_inplace(plain_coeff0);
    cout << "#### The pool3 Done [" << time_diff.count() << " microseconds]" << endl;

    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer Rot latency is  [" << Rot_latency[i] / 1000 << " ms]"
             << " Mult latency is " << +Mul_latency[i] / 1000 << " ms]" << endl;
    }

    double Rot_latency_total = 0.0;
    double Mult_latency_total = 0.0;
    for (int i = 0; i < 13; i++)
    {
        cout << "The " << i << " layer **Total** Rot latency is  [" << Rot_Cost[i] << " ms]"
             << " **Total** Mult latency is " << +Mul_Cost[i] << " ms]" << endl;
        Rot_latency_total += Rot_Cost[i];
        Mult_latency_total += Mul_Cost[i];
    }

    cout << "The Rot latency is  [" << Rot_latency_total << " ms]"
         << " Mult latency is " << +Mult_latency_total << " ms]"
         << " Total latency is " << +(Rot_latency_total + Mult_latency_total) / 1000 << " s]" << endl;
}


void example_squeezenet()
{
    squeeze();
    remove_fire4();
    remove_fire34();
    remove_fire234();
    remove_fire34_merge();
}
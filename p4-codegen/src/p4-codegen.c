/**
 * @file p4-codegen.c
 * @brief Compiler phase 4: code generation
 *
 * Mitch Kehoe and Christian Guerrero
 * Used AI for help with prologue and epilogue
 */
#include "p4-codegen.h"

/**
 * @brief State/data for the code generator visitor
 */
typedef struct CodeGenData
{
    /**
     * @brief Reference to the epilogue jump label for the current function
     */
    Operand current_epilogue_jump_label;

    /* add any new desired state information (and clean it up in CodeGenData_free) */
} CodeGenData;

/**
 * @brief Allocate memory for code gen data
 *
 * @returns Pointer to allocated structure
 */
CodeGenData *CodeGenData_new(void)
{
    CodeGenData *data = (CodeGenData *)calloc(1, sizeof(CodeGenData));
    CHECK_MALLOC_PTR(data);
    data->current_epilogue_jump_label = empty_operand();
    return data;
}

/**
 * @brief Deallocate memory for code gen data
 *
 * @param data Pointer to the structure to be deallocated
 */
void CodeGenData_free(CodeGenData *data)
{
    /* free everything in data that is allocated on the heap */

    /* free "data" itself */
    free(data);
}

/**
 * @brief Macro for more convenient access to the error list inside a @c visitor
 * data structure
 */
#define DATA ((CodeGenData *)visitor->data)

/**
 * @brief Fills a register with the base address of a variable.
 *
 * @param node AST node to emit code into (if needed)
 * @param variable Desired variable
 * @returns Virtual register that contains the base address
 */
Operand var_base(ASTNode *node, Symbol *variable)
{
    Operand reg = empty_operand();
    switch (variable->location)
    {
    case STATIC_VAR:
        reg = virtual_register();
        ASTNode_emit_insn(node,
                          ILOCInsn_new_2op(LOAD_I, int_const(variable->offset), reg));
        break;
    case STACK_PARAM:
    case STACK_LOCAL:
        reg = base_register();
        break;
    default:
        break;
    }
    return reg;
}

/**
 * @brief Calculates the offset of a scalar variable reference and fills a register with that offset.
 *
 * @param node AST node to emit code into (if needed)
 * @param variable Desired variable
 * @returns Virtual register that contains the base address
 */
Operand var_offset(ASTNode *node, Symbol *variable)
{
    Operand op = empty_operand();
    switch (variable->location)
    {
    case STATIC_VAR:
        op = int_const(0);
        break;
    case STACK_PARAM:
    case STACK_LOCAL:
        op = int_const(variable->offset);
        break;
    default:
        break;
    }
    return op;
}

#ifndef SKIP_IN_DOXYGEN

/*
 * Macros for more convenient instruction generation
 */

#define EMIT0OP(FORM) ASTNode_emit_insn(node, ILOCInsn_new_0op(FORM))
#define EMIT1OP(FORM, OP1) ASTNode_emit_insn(node, ILOCInsn_new_1op(FORM, OP1))
#define EMIT2OP(FORM, OP1, OP2) ASTNode_emit_insn(node, ILOCInsn_new_2op(FORM, OP1, OP2))
#define EMIT3OP(FORM, OP1, OP2, OP3) ASTNode_emit_insn(node, ILOCInsn_new_3op(FORM, OP1, OP2, OP3))

void CodeGenVisitor_gen_program(NodeVisitor *visitor, ASTNode *node)
{
    /*
     * make sure "code" attribute exists at the program level even if there are
     * no functions (although this shouldn't happen if static analysis is run first)
     */
    ASTNode_set_attribute(node, "code", InsnList_new(), (Destructor)InsnList_free);

    /* copy code from each function */
    FOR_EACH(ASTNode *, func, node->program.functions)
    {
        ASTNode_copy_code(node, func);
    }
}

void CodeGenVisitor_previsit_funcdecl(NodeVisitor *visitor, ASTNode *node)
{
    /* generate a label reference for the epilogue that can be used while
     * generating the rest of the function (e.g., to be used when generating
     * code for a "return" statement) */
    DATA->current_epilogue_jump_label = anonymous_label();
}

void CodeGenVisitor_gen_funcdecl(NodeVisitor *visitor, ASTNode *node)
{
    /* every function begins with the corresponding call label */
    EMIT1OP(LABEL, call_label(node->funcdecl.name));

    /* BOILERPLATE: TODO: implement prologue */
    EMIT1OP(PUSH, base_register());
    EMIT2OP(I2I, stack_register(), base_register());

    long local_size = (long)ASTNode_get_attribute(node, "localSize");
    /*if (local_size > 0)
    {
        EMIT3OP(ADD_I, stack_register(), int_const(-local_size), stack_register());
    }*/
    // Always emit even if local size is 0
    EMIT3OP(ADD_I, stack_register(), int_const(-local_size), stack_register());

    /* copy code from body */
    ASTNode_copy_code(node, node->funcdecl.body);

    EMIT1OP(LABEL, DATA->current_epilogue_jump_label);

    /* BOILERPLATE: TODO: implement epilogue */
    EMIT2OP(I2I, base_register(), stack_register());
    EMIT1OP(POP, base_register());
    EMIT0OP(RETURN);
}

void CodeGenVisitor_gen_block(NodeVisitor *visitor, ASTNode *node)
{
    FOR_EACH(ASTNode *, stmt, node->block.statements)
    {
        ASTNode_copy_code(node, stmt);
    }
}

void CodeGenVisitor_gen_return(NodeVisitor *visitor, ASTNode *node)
{
    if (node->funcreturn.value)
    {
        ASTNode_copy_code(node, node->funcreturn.value);
        Operand reg = ASTNode_get_temp_reg(node->funcreturn.value);
        EMIT2OP(I2I, reg, return_register());
    }
    // jump to epilogue
    EMIT1OP(JUMP, DATA->current_epilogue_jump_label);
}

void CodeGenVisitor_gen_literal(NodeVisitor *visitor, ASTNode *node)
{
    Operand reg = virtual_register();
    ASTNode_set_temp_reg(node, reg);
    EMIT2OP(LOAD_I, int_const(node->literal.integer), reg);
}

void CodeGenVisitor_gen_binop(NodeVisitor *visitor, ASTNode *node)
{
    // TODO add more than just + for C level
    // TODO add modop later

    // copy left and get reg
    ASTNode_copy_code(node, node->binaryop.left);
    Operand left = ASTNode_get_temp_reg(node->binaryop.left);
    // copy right and get reg
    ASTNode_copy_code(node, node->binaryop.right);
    Operand right = ASTNode_get_temp_reg(node->binaryop.right);
    Operand newReg = virtual_register();
    ASTNode_set_temp_reg(node, newReg);

    BinaryOpType binop = node->binaryop.operator;

    switch (binop)
    {
    case OROP:
        EMIT3OP(OR, left, right, newReg);
        break;
    case ANDOP:
        EMIT3OP(AND, left, right, newReg);
        break;
    case EQOP:
        EMIT3OP(CMP_EQ, left, right, newReg);
        break;
    case NEQOP:
        EMIT3OP(CMP_NE, left, right, newReg);
        break;
    case LTOP:
        EMIT3OP(CMP_LT, left, right, newReg);
        break;
    case LEOP:
        EMIT3OP(CMP_LE, left, right, newReg);
        break;
    case GEOP:
        EMIT3OP(CMP_GE, left, right, newReg);
        break;
    case GTOP:
        EMIT3OP(CMP_GT, left, right, newReg);
        break;
    case ADDOP:
        EMIT3OP(ADD, left, right, newReg);
        break;
    case SUBOP:
        EMIT3OP(SUB, left, right, newReg);
        break;
    case MULOP:
        EMIT3OP(MULT, left, right, newReg);
        break;
    case DIVOP:
        EMIT3OP(DIV, left, right, newReg);
        break;
    case MODOP:;
        // Set up registers to store additional calculations
        Operand divReg = virtual_register();
        Operand multReg = virtual_register();

        // Calculate modulo value by calculating remainder
        EMIT3OP(DIV, left, right, divReg);
        EMIT3OP(MULT, divReg, right, multReg);
        EMIT3OP(SUB, left, multReg, newReg);
        break;
    default:
        break;
    }
}

void CodeGenVisitor_gen_unaryop(NodeVisitor *visitor, ASTNode *node)
{
    // copy child code and get register
    ASTNode_copy_code(node, node->unaryop.child);
    Operand childReg = ASTNode_get_temp_reg(node->unaryop.child);

    UnaryOpType op = node->unaryop.operator;
    Operand newReg = virtual_register();
    ASTNode_set_temp_reg(node, newReg);
    if (op == NEGOP)
    {
        // negative num case -4
        EMIT2OP(NEG, childReg, newReg);
    }
    else if (op == NOTOP)
    {
        // not operator case !true
        EMIT2OP(NOT, childReg, newReg);
    }
}

void CodeGenVisitor_gen_location(NodeVisitor *visitor, ASTNode *node)
{
    // Get symbol and base pointer
    Symbol *sym = lookup_symbol(node, node->location.name);
    Operand basePointer = var_base(node, sym);
    if (!node->location.index)
    {
        // Non Array Case
        Operand offset = var_offset(node, sym);
        Operand newReg = virtual_register();
        ASTNode_set_temp_reg(node, newReg);
        EMIT3OP(LOAD_AI, basePointer, offset, newReg);
        return;
    }

    // Array case
    ASTNode_copy_code(node, node->location.index);
    Operand expReg = ASTNode_get_temp_reg(node->location.index);

    // calc word size
    Operand offsetReg = virtual_register();
    Operand wordSize = int_const(WORD_SIZE);
    EMIT3OP(MULT_I, expReg, wordSize, offsetReg);

    // load value
    Operand newReg = virtual_register();
    ASTNode_set_temp_reg(node, newReg);

    // Load value into register
    EMIT3OP(LOAD_AO, basePointer, offsetReg, newReg);
}

void CodeGenVisitor_gen_assignment(NodeVisitor *visitor, ASTNode *node)
{
    // Get base pointer and offset
    Symbol *sym = lookup_symbol(node, node->assignment.location->location.name);
    Operand basePointer = var_base(node, sym);
    Operand expReg;

    if (!node->assignment.location->location.index)
    {
        // Non array case
        Operand offset = var_offset(node, sym);
        // Copy expression and get register
        ASTNode_copy_code(node, node->assignment.value);
        expReg = ASTNode_get_temp_reg(node->assignment.value);

        // Create ILOC code
        EMIT3OP(STORE_AI, expReg, basePointer, offset);
        return;
    }

    // Array case
    // Get expression code and register
    ASTNode_copy_code(node, node->assignment.location->location.index);
    expReg = ASTNode_get_temp_reg(node->assignment.location->location.index);

    // Get assigned value
    ASTNode_copy_code(node, node->assignment.value);
    Operand valReg = ASTNode_get_temp_reg(node->assignment.value);

    // Calculate offset value
    Operand offsetReg = virtual_register();
    Operand wordSize = int_const(WORD_SIZE);
    EMIT3OP(MULT_I, expReg, wordSize, offsetReg);

    EMIT3OP(STORE_AO, valReg, basePointer, offsetReg);
}

void CodeGenVisitor_gen_conditional(NodeVisitor *visitor, ASTNode *node)
{
    // get conditional code and register
    ASTNode_copy_code(node, node->conditional.condition);
    Operand conditionalReg = ASTNode_get_temp_reg(node->conditional.condition);

    // Create and store labels
    Operand label1 = anonymous_label();
    Operand label2 = anonymous_label();

    // Generate ILOC
    EMIT3OP(CBR, conditionalReg, label1, label2);
    EMIT1OP(LABEL, label1);
    ASTNode_copy_code(node, node->conditional.if_block);
    if (!node->conditional.else_block)
    {
        // If only case
        EMIT1OP(LABEL, label2);
    }
    else
    {
        // If + else case
        Operand label3 = anonymous_label();
        EMIT1OP(JUMP, label3);
        EMIT1OP(LABEL, label2);
        ASTNode_copy_code(node, node->conditional.else_block);
        EMIT1OP(LABEL, label3);
    }
}

void CodeGenVisitor_previsit_while(NodeVisitor *visitor, ASTNode *node)
{
    // Generate all three labels for while loop
    Operand label1 = anonymous_label();
    Operand label2 = anonymous_label();
    Operand label3 = anonymous_label();

    // Set for use in postvisit while
    Operand *continue_label = malloc(sizeof(Operand));
    Operand *body_label = malloc(sizeof(Operand));
    Operand *break_label = malloc(sizeof(Operand));

    *continue_label = label1;
    *body_label = label2;
    *break_label = label3;

    ASTNode_set_attribute(node, "l1", continue_label, free);
    ASTNode_set_attribute(node, "l2", body_label, free);
    ASTNode_set_attribute(node, "l3", break_label, free);
}

void CodeGenVisitor_gen_while(NodeVisitor *visitor, ASTNode *node)
{
    // Get labels previously set
    Operand label1 = *(Operand *)ASTNode_get_attribute(node, "l1");
    Operand label2 = *(Operand *)ASTNode_get_attribute(node, "l2");
    Operand label3 = *(Operand *)ASTNode_get_attribute(node, "l3");

    // Generate ILOC
    EMIT1OP(LABEL, label1);
    // copy conditional
    ASTNode_copy_code(node, node->whileloop.condition);
    Operand condReg = ASTNode_get_temp_reg(node->whileloop.condition);
    // evaluate conditional and copy body at each iteration
    EMIT3OP(CBR, condReg, label2, label3);
    EMIT1OP(LABEL, label2);
    ASTNode_copy_code(node, node->whileloop.body);
    // jump to top
    EMIT1OP(JUMP, label1);
    EMIT1OP(LABEL, label3);
}

/**
 * Helper method to find while loop which continue and break belong to
 */
ASTNode *find_while_parent_helper(ASTNode *node)
{
    ASTNode *parent = (ASTNode *)ASTNode_get_attribute(node, "parent");
    while (parent->type != WHILELOOP)
    {
        // recurse upward to find parent while loop
        parent = (ASTNode *)ASTNode_get_attribute(parent, "parent");
    }
    return parent;
}

void CodeGenVisitor_gen_continue(NodeVisitor *visitor, ASTNode *node)
{
    // find parent while loop
    ASTNode *parent = find_while_parent_helper(node);

    // get label from parent and emit jump instruction
    Operand label = *(Operand *)ASTNode_get_attribute(parent, "l1");
    EMIT1OP(JUMP, label);
}

void CodeGenVisitor_gen_break(NodeVisitor *visitor, ASTNode *node)
{
    // find parent while loop
    ASTNode *parent = find_while_parent_helper(node);

    // get label from parent and emit jump instruction
    Operand label = *(Operand *)ASTNode_get_attribute(parent, "l3");
    EMIT1OP(JUMP, label);
}

static bool is_builtin_print(const char *name)
{
    return strncmp(name, "print_int", 16) == 0 ||
           strncmp(name, "print_bool", 16) == 0 ||
           strncmp(name, "print_str", 16) == 0;
}

void CodeGenVisitor_gen_funccall(NodeVisitor *visitor, ASTNode *node)
{

    const char *fname = node->funccall.name;

    /* Handle built-in prints with a single PRINT */
    if (is_builtin_print(fname))
    {
        /* exactly one argument */
        ASTNode *arg = NULL;
        FOR_EACH(ASTNode *, a, node->funccall.arguments)
        {
            arg = a;
            break;
        }

        /* safety: if there's somehow no arg, just return */
        if (!arg)
            return;

        ASTNode_copy_code(node, arg);

        if (strncmp(fname, "print_str", 16) == 0)
        {
            if (arg->type == LITERAL && arg->literal.type == STR)
            {
                EMIT1OP(PRINT, str_const(arg->literal.string));
            }
            else
            {
                /* fallback: print the evaluated register numerically */
                Operand areg = ASTNode_get_temp_reg(arg);
                EMIT1OP(PRINT, areg);
            }
        }
        else
        {
            /* print_int / print_bool: print evaluated integer/boolean register */
            Operand areg = ASTNode_get_temp_reg(arg);
            EMIT1OP(PRINT, areg);
        }
        return;
    }

    int argc = node->funccall.arguments->size;
    // make array to hold param regs
    Operand *arg_regs = (Operand *)calloc(argc, sizeof(Operand));
    CHECK_MALLOC_PTR(arg_regs);

    int i = 0;
    FOR_EACH(ASTNode *, arg, node->funccall.arguments)
    {
        // copy codeto reg
        ASTNode_copy_code(node, arg);
        arg_regs[i++] = ASTNode_get_temp_reg(arg);
    }

    for (int j = argc - 1; j >= 0; --j)
    {
        EMIT1OP(PUSH, arg_regs[j]);
    }
    free(arg_regs);
    EMIT1OP(CALL, call_label(fname));

    EMIT3OP(ADD_I, stack_register(), int_const(8 * argc), stack_register());
    Operand retReg = virtual_register();
    EMIT2OP(I2I, return_register(), retReg);
    ASTNode_set_temp_reg(node, retReg);
}

#endif
InsnList *generate_code(ASTNode *tree)
{
    if (!tree)
    {
        return 0;
    }
    InsnList *iloc = InsnList_new();

    NodeVisitor *v = NodeVisitor_new();
    v->data = CodeGenData_new();
    v->dtor = (Destructor)CodeGenData_free;
    v->postvisit_program = CodeGenVisitor_gen_program;
    v->previsit_funcdecl = CodeGenVisitor_previsit_funcdecl;
    v->postvisit_funcdecl = CodeGenVisitor_gen_funcdecl;
    v->postvisit_block = CodeGenVisitor_gen_block;
    v->postvisit_return = CodeGenVisitor_gen_return;
    v->postvisit_literal = CodeGenVisitor_gen_literal;
    v->postvisit_binaryop = CodeGenVisitor_gen_binop;
    v->postvisit_unaryop = CodeGenVisitor_gen_unaryop;
    v->postvisit_location = CodeGenVisitor_gen_location;
    v->postvisit_assignment = CodeGenVisitor_gen_assignment;
    v->postvisit_conditional = CodeGenVisitor_gen_conditional;
    v->previsit_whileloop = CodeGenVisitor_previsit_while;
    v->postvisit_whileloop = CodeGenVisitor_gen_while;
    v->postvisit_continue = CodeGenVisitor_gen_continue;
    v->postvisit_break = CodeGenVisitor_gen_break;
    v->postvisit_funccall = CodeGenVisitor_gen_funccall;

    /* generate code into AST attributes */
    NodeVisitor_traverse_and_free(v, tree);

    /* copy generated code into new list (the AST may be deallocated before
     * the ILOC code is needed) */
    FOR_EACH(ILOCInsn *, i, (InsnList *)ASTNode_get_attribute(tree, "code"))
    {
        InsnList_add(iloc, ILOCInsn_copy(i));
    }
    return iloc;
}
